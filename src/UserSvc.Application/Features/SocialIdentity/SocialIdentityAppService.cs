using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Security;
using UserSvc.Domain.Users;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// Signing in and binding with WeChat, the WeChat mini program, Firebase (Google / Apple /
/// Facebook) and LINE.
/// <para>
/// <b>The provider clients are the small part.</b> Exchanging a code for an openid is one HTTP
/// call; deciding <i>which account</i> that openid belongs to is where the whole slice lives, and
/// it is the part that needs no credentials at all to be right or wrong. Each provider resolves
/// through an ordered list of keys, and the order is the contract - see
/// <see cref="ResolveWechatAsync"/> and <see cref="ResolveLineAsync"/>.
/// </para>
/// <para>
/// <b>Nothing here mints a token</b> (decision 10). A sign-in resolves an account and stops;
/// <c>/connect/token</c> issues the session, exactly as it does after registration. That also
/// closes a hole the original had: the WeChat path never checked the account's status before
/// issuing a token pair, and here the token endpoint refuses a non-ACTIVE account regardless.
/// </para>
/// <para>
/// <b>Provider subjects are identifiers like any other</b> (decision 13). An openid, a LINE sub
/// and a Firebase uid all go through <see cref="IdentifierProtector"/>: blind index in
/// <c>identifier_hash</c>, ciphertext in <c>identifier_ciphertext</c>. None of them sits in a
/// column in the clear. The values that <i>are</i> in the clear - <c>provider</c> and
/// <c>provider_uid</c> - are there because they carry a unique index a hash cannot, and because
/// neither is a credential.
/// </para>
/// </summary>
/// <summary>
/// The provider clients are injected as FACTORIES, not instances, and that is load-bearing rather
/// than fussy.
/// <para>
/// This one service fronts four independent capabilities. Taking the clients directly meant
/// constructing it constructed all four - which ran each typed client's configuration, which read
/// each provider's validated options - so a deployment holding only a LINE channel id answered 500
/// on the LINE endpoint too, complaining about a WeChat secret it never needed. Measured, not
/// theorised: that was the observed behaviour before this change.
/// </para>
/// <para>
/// Resolving on use means an unconfigured provider fails on its own endpoints and nowhere else. It
/// is the same rule as a placeholder that must refuse where the capability is missing rather than
/// where it is merely reachable.
/// </para>
/// </summary>
public sealed class SocialIdentityAppService(
    IUserRepository users,
    IUserIdentityRepository identities,
    Func<IWechatClient> wechat,
    Func<IWechatMiniClient> wechatMini,
    Func<ILineClient> line,
    Func<IFirebaseTokenVerifier> firebase,
    OAuthStateService states,
    SocialBindingTokenService bindingTokens,
    IdentifierProtector protector,
    IUnitOfWork unitOfWork,
    IClock clock,
    IOptions<SocialIdentityOptions> socialOptions,
    IOptions<WechatOptions> wechatOptions,
    IOptions<LineOptions> lineOptions,
    ILogger<SocialIdentityAppService> logger)
{
        // Read at the point of use, NOT in the constructor. IOptions<T>.Value is what runs
        // DataAnnotations validation, so reading it eagerly throws OptionsValidationException
        // while this type is merely being CONSTRUCTED - and SocialIdentityAppService takes all
        // four providers in its constructor, so one missing credential made every provider's
        // endpoint answer 500. Deferring the read means an unconfigured provider fails only on
        // its own endpoints. Value is cached after the first successful read, so this costs nothing.
    private SocialIdentityOptions _social => socialOptions.Value;
    private WechatOptions _wechat => wechatOptions.Value;
    private LineOptions _line => lineOptions.Value;

    // =================================================================== authorization start

    /// <summary>
    /// Everything the client needs to send the user to WeChat: the AppID, the scope this
    /// deployment asks for, and a signed state.
    /// <para>
    /// A missing device id is not an error. A browser redirect carries no device header, and
    /// refusing here would make web OAuth impossible while protecting nothing - the state's value
    /// is its signature, not its payload.
    /// </para>
    /// </summary>
    public WechatOAuthStartResponse StartWechatOAuth(string deviceId) => new()
    {
        AppId = _wechat.AppId,
        State = states.Issue(deviceId),
        Scope = _wechat.Scope,
    };

    /// <summary>
    /// The same for LINE, plus the nonce. LINE binds the id_token to a nonce the client supplies,
    /// and handing back the state's own random component is what lets the server re-check that
    /// binding later without having stored a thing.
    /// </summary>
    public LineOAuthStartResponse StartLineOAuth(string deviceId)
    {
        var state = states.Issue(deviceId);

        return new LineOAuthStartResponse
        {
            ChannelId = _line.ChannelId,
            State = state,
            Nonce = states.ReadNonce(state),
            Scope = _line.Scope,
        };
    }

    // =================================================================== WeChat sign-in

    /// <summary>Sign in with a WeChat web OAuth code.</summary>
    public async Task<SocialSignInResponse> SignInWithWechatAsync(
        WechatSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Before the network call, not after: an unverifiable state means this redirect is not one
        // we started, and there is no reason to spend a WeChat round trip finding that out.
        states.ReadDeviceId(request.State);

        var exchange = await wechat().ExchangeCodeAsync(request.Code, cancellationToken);

        var resolved = await ResolveWechatAsync(
            IdentityTypes.Wechat,
            SocialProviders.None,
            exchange.OpenId,
            exchange.UnionId,
            phone: string.Empty,
            cancellationToken);

        // Deliberately no last-login write here, while LINE and Firebase do write one. The
        // divergence is the original's and is preserved: WeChat sign-in has never advanced
        // last_login_at, and dashboards built on that column would shift the day it started to.
        return await DescribeAsync(resolved.User, resolved.IsNewUser, cancellationToken);
    }

    /// <summary>
    /// Sign in from the WeChat mini program, optionally redeeming the phone-number code the user
    /// tapped through.
    /// <para>
    /// <b>The phone number is resolved before the account is, on purpose.</b> It is the third key
    /// account resolution can match on, so fetching it up front lets a mini-program sign-in find
    /// the account the user already has by phone number instead of creating a second one. Every
    /// part of that is best effort: if WeChat will not hand over the number, the flow falls through
    /// to openid and union-id matching and the user still signs in.
    /// </para>
    /// </summary>
    public async Task<SocialSignInResponse> SignInWithWechatMiniAsync(
        WechatMiniSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.Code))
        {
            throw new BadRequestException(ErrorCodes.WechatLoginFailed, "A WeChat sign-in code is required.");
        }

        var exchange = await wechatMini().ExchangeSessionAsync(request.Code, cancellationToken);
        var phone = await TryResolveMiniProgramPhoneAsync(request.PhoneCode, cancellationToken);

        var resolved = await ResolveWechatAsync(
            IdentityTypes.WechatMini,
            SocialProviders.WechatMiniProgram,
            exchange.OpenId,
            exchange.UnionId,
            phone,
            cancellationToken);

        // Only when resolution did not already deal with it. It did when the phone was the key that
        // found the account, or when the account was created around it; what is left is the case
        // where openid or union id won, and the number is simply one this account does not have yet.
        if (phone.Length > 0 && !resolved.PhoneHandled)
        {
            await TryAttachPhoneAsync(resolved.User, phone, cancellationToken);
        }

        return await DescribeAsync(resolved.User, resolved.IsNewUser, cancellationToken);
    }

    /// <summary>
    /// Attach a WeChat web identity to the signed-in account.
    /// </summary>
    public async Task BindWechatAsync(int userId, WechatSignInRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        states.ReadDeviceId(request.State);

        var exchange = await ExchangeForBindAsync(
            () => wechat().ExchangeCodeAsync(request.Code, cancellationToken));

        await BindProviderIdentityAsync(
            userId,
            IdentityTypes.Wechat,
            SocialProviders.None,
            exchange.OpenId,
            exchange.UnionId,
            ProviderDetailsFor(exchange.UnionId),
            "WeChat",
            cancellationToken);
    }

    /// <summary>Attach a WeChat mini-program identity to the signed-in account.</summary>
    public async Task BindWechatMiniAsync(
        int userId,
        WechatMiniSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var exchange = await ExchangeForBindAsync(async () =>
        {
            var session = await wechatMini().ExchangeSessionAsync(request.Code, cancellationToken);
            return new WechatCodeExchange(session.OpenId, session.UnionId);
        });

        await BindProviderIdentityAsync(
            userId,
            IdentityTypes.WechatMini,
            SocialProviders.WechatMiniProgram,
            exchange.OpenId,
            exchange.UnionId,
            ProviderDetailsFor(exchange.UnionId),
            "WeChat",
            cancellationToken);
    }

    // =================================================================== LINE sign-in

    /// <summary>
    /// Sign in with a LINE id_token.
    /// <para>
    /// <b>Every failure on this path answers <c>LINE_LOGIN_FAILED</c></b>, including a bad state -
    /// which the WeChat path reports as <c>INVALID_STATE</c>. That is the original's contract and
    /// the LINE clients branch on it, so the state failure is deliberately re-labelled here rather
    /// than left to surface as itself.
    /// </para>
    /// </summary>
    public async Task<SocialSignInResponse> SignInWithLineAsync(
        LineSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var nonce = ReadLineNonce(request.State);
        var identity = await line().VerifyIdTokenAsync(request.IdToken, nonce, cancellationToken);
        var resolved = await ResolveLineAsync(identity, cancellationToken);

        // LINE answers ACCOUNT_DISABLED where WeChat and Firebase answer ACCOUNT_NOT_ACTIVATED for
        // the identical condition. Two codes for one state is not something to tidy up: the LINE
        // clients branch on this one and have since before the others existed.
        if (!resolved.User.IsActive())
        {
            throw new ForbiddenException(ErrorCodes.AccountDisabled, "This account is not active.");
        }

        await TouchLastLoginAsync(resolved.User, cancellationToken);

        return await DescribeAsync(resolved.User, resolved.IsNewUser, cancellationToken);
    }

    /// <summary>Attach a LINE identity to the signed-in account.</summary>
    public async Task BindLineAsync(int userId, LineSignInRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var nonce = ReadLineNonce(request.State);

        // Note the asymmetry with BindWechatAsync, which reports BIND_FAILED: LINE reports
        // LINE_LOGIN_FAILED on the bind path too. Preserved from the original for the same reason
        // as above - it is what the clients read.
        var identity = await line().VerifyIdTokenAsync(request.IdToken, nonce, cancellationToken);

        await BindProviderIdentityAsync(
            userId,
            IdentityTypes.Line,
            SocialProviders.None,
            identity.Sub,
            providerUid: string.Empty,
            new ProviderDetails(
                EmailMasked: SocialProfileText.Mask(IdentityTypes.Email, identity.Email),
                Name: identity.Name),
            "LINE",
            cancellationToken);
    }

    // =================================================================== Firebase sign-in

    /// <summary>
    /// Sign in with a Firebase ID token.
    /// <para>
    /// It has one outcome the other providers do not: when the verified address already belongs to
    /// an account here, nothing is linked and nothing is created. The response carries a signed
    /// proposal instead, and the human decides at <see cref="ConfirmFirebaseBindingAsync"/>.
    /// </para>
    /// <para>
    /// <b>Why Firebase asks and LINE does not</b> is worth stating, because the asymmetry is
    /// deliberate and is preserved from the original. A Firebase token can come from any provider
    /// the console has enabled, including ones whose address assertions vary in strength, and the
    /// accounts it would merge into are the ones registered by email and password. The consent
    /// screen is the compensating control. The LINE path merges silently on the same signal, which
    /// is the weaker of the two designs; it is kept because changing it would silently orphan every
    /// LINE user who has been relying on it, and closing it properly is a contract change rather
    /// than an edit during a port.
    /// </para>
    /// </summary>
    public async Task<FirebaseSignInResponse> SignInWithFirebaseAsync(
        FirebaseSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var provider = RequireAllowedFirebaseProvider(request.Provider);
        var token = await VerifyFirebaseAsync(request.FirebaseIdToken, provider, cancellationToken);

        // 1. The uid we already know. A returning user stops here, and - importantly - never
        //    reaches the email match below, so a second sign-in never re-asks for consent.
        var existing = await identities.FindActiveByIdentifierAndProviderAsync(
            IdentityTypes.Firebase, HashOf(IdentityTypes.Firebase, token.Uid), provider, cancellationToken);

        if (existing is not null)
        {
            return await CompleteFirebaseSignInAsync(existing.UserId, token, provider, isNewUser: false, cancellationToken);
        }

        // 2. The provider's own subject. The uid lookup misses whenever Firebase deleted and
        //    re-created its user record for this same Google or Apple account, because that mints a
        //    fresh uid while the provider's sub never moves. Falling back to the key the unique
        //    index actually enforces is what keeps a returning user out of the consent flow on
        //    every single login; the stored identifier is then re-pointed so the fast path works
        //    again next time.
        if (token.ProviderUid.Length > 0)
        {
            var byProviderKey = await identities.FindActiveByProviderAsync(
                IdentityTypes.Firebase, provider, token.ProviderUid, cancellationToken);

            if (byProviderKey is not null)
            {
                await TryRepointFirebaseIdentifierAsync(byProviderKey, token.Uid, cancellationToken);

                return await CompleteFirebaseSignInAsync(
                    byProviderKey.UserId, token, provider, isNewUser: false, cancellationToken);
            }
        }

        // 3. The address, when there is a usable one. An Apple private-relay address is not one -
        //    see FirebaseEmailRules - so an Apple user who hid their address takes the branch below
        //    and gets a fresh account, which is the only honest answer.
        var email = FirebaseEmailRules.UsableEmail(token.Email);
        if (email.Length > 0)
        {
            var emailIdentity = await identities.FindActiveAsync(
                IdentityTypes.Email, HashOf(IdentityTypes.Email, email), cancellationToken);

            if (emailIdentity is not null)
            {
                return ProposeFirebaseBinding(token, provider, emailIdentity, email);
            }
        }

        // 4. Nobody owns this uid, this provider subject or this address: a new account.
        var created = await CreateFirebaseAccountAsync(token, provider, email, cancellationToken);

        return await CompleteFirebaseSignInAsync(created, token, provider, isNewUser: true, cancellationToken);
    }

    /// <summary>
    /// The answer to the consent screen. Confirming attaches the Firebase identity to the account
    /// named inside the signed proposal - never to one the client names, which is why the proposal
    /// is signed at all.
    /// </summary>
    public async Task<ConfirmFirebaseBindingResponse> ConfirmFirebaseBindingAsync(
        ConfirmFirebaseBindingRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var proposal = bindingTokens.Open(request.BindingToken);

        if (!request.Confirm)
        {
            // Nothing is read, nothing is written, and in particular nothing is said about whether
            // the target account exists - declining must not be a way to probe for one.
            return new ConfirmFirebaseBindingResponse { Status = FirebaseBindingStatuses.Canceled };
        }

        var user = await users.FindByIdAsync(proposal.TargetUserId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "The account was not found.");

        RequireActive(user, ErrorCodes.AccountNotActivated);

        await AttachFirebaseIdentityAsync(
            user,
            proposal.FirebaseUid,
            proposal.Provider,
            proposal.ProviderUid,
            new ProviderDetails(EmailMasked: proposal.EmailMasked, Name: proposal.Name),
            cancellationToken);

        await TouchLastLoginAsync(user, cancellationToken);

        return new ConfirmFirebaseBindingResponse
        {
            Status = FirebaseBindingStatuses.Confirmed,
            Account = await DescribeAsync(user, isNewUser: false, cancellationToken),
        };
    }

    /// <summary>
    /// Attach a Firebase identity to the account already signed in. No consent screen: the caller
    /// holds a session on the target account, which is the consent.
    /// </summary>
    public async Task BindFirebaseAsync(
        int userId,
        FirebaseSignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var provider = RequireAllowedFirebaseProvider(request.Provider);
        var token = await VerifyFirebaseAsync(request.FirebaseIdToken, provider, cancellationToken);

        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "The account was not found.");

        await AttachFirebaseIdentityAsync(
            user,
            token.Uid,
            provider,
            token.ProviderUid,
            new ProviderDetails(
                EmailMasked: SocialProfileText.Mask(
                    IdentityTypes.Email, FirebaseEmailRules.UsableEmail(token.Email)),
                Name: token.Name),
            cancellationToken);
    }

    // =================================================================== unbind

    /// <summary>
    /// Detach a third-party identity from the signed-in account.
    /// <para>
    /// <b>The row is retired, not deleted</b>: status becomes <c>UNBOUND</c>, which drops it out of
    /// the partial unique index so the same provider account can later be attached somewhere else,
    /// while the history of it having been here survives. A physical delete would make an
    /// account-takeover investigation impossible.
    /// </para>
    /// <para>
    /// <b>It refuses to remove the last way in.</b> An account whose only identity is the one being
    /// unbound, and which has no password, would become unreachable by its owner and unrecoverable
    /// by support - a 409 pointing at "add another sign-in method first" is the only useful answer.
    /// The check counts <i>other</i> active identities, so unbinding one of two is always allowed.
    /// </para>
    /// </summary>
    public async Task UnbindAsync(
        int userId,
        string identityType,
        string provider,
        CancellationToken cancellationToken)
    {
        var normalizedType = RequireSocialIdentityType(identityType);
        var normalizedProvider = provider ?? SocialProviders.None;

        var all = await identities.ListActiveByUserAsync(userId, cancellationToken);

        var target = all.FirstOrDefault(i =>
            i.IdentityType == normalizedType && i.Provider == normalizedProvider);

        if (target is null)
        {
            throw new NotFoundException(
                ErrorCodes.NotFound, "That sign-in method is not linked to this account.");
        }

        if (all.Count(i => i.Id != target.Id) == 0)
        {
            var user = await users.FindByIdAsync(userId, cancellationToken);
            if (string.IsNullOrEmpty(user?.PasswordHash))
            {
                throw new ConflictException(
                    ErrorCodes.LastLoginMethod,
                    "This is the only way to sign in to this account. Add another one before removing it.");
            }
        }

        target.Status = UserStatuses.Unbound;
        target.UpdatedAt = clock.UtcNow;
        identities.Update(target);
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    // =================================================================== WeChat resolution

    /// <summary>
    /// Which account a WeChat credential belongs to, decided by four keys in a fixed order.
    /// <list type="number">
    /// <item>
    /// <b>The openid for this exact application.</b> The stable per-app primary key, and the only
    /// one that is exact. A returning user stops here and nothing else is consulted.
    /// </item>
    /// <item>
    /// <b>The union id.</b> Same human, different WeChat application - the mini program and the
    /// website issue different openids to one person, and this is the only signal that says so. A
    /// new identity row is attached to the account that already exists; no second account.
    /// </item>
    /// <item>
    /// <b>The phone number</b>, when the mini program handed one over. A person who registered by
    /// phone and now taps "sign in with WeChat" gets their existing account, not a duplicate. The
    /// phone identity itself is left exactly where it is - the WeChat identity moves to it, never
    /// the other way round.
    /// </item>
    /// <item>Otherwise a brand-new account, with the phone bound in the same transaction so it is complete the moment it exists.</item>
    /// </list>
    /// <para>
    /// <b>Union id outranks the phone number, and that ordering decides a real conflict.</b> When
    /// the union id points at account A and the phone number at a different account B, the sign-in
    /// resolves to A and B is left alone - the phone is only ever a hint, while the union id is
    /// WeChat asserting these are the same person. Accounts are never merged automatically once one
    /// has been resolved.
    /// </para>
    /// </summary>
    private async Task<WechatResolution> ResolveWechatAsync(
        string identityType,
        string provider,
        string openId,
        string unionId,
        string phone,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(openId))
        {
            // The adapters already refuse an empty openid; this is the second line, because an
            // empty identifier would hash to one value shared by every such request - one account
            // for everybody.
            throw new BadRequestException(ErrorCodes.WechatLoginFailed, "WeChat returned no account identifier.");
        }

        var details = ProviderDetailsFor(unionId);

        // (1) Exact match on this application's openid.
        var existing = await identities.FindActiveAsync(
            identityType, HashOf(identityType, openId), cancellationToken);

        if (existing is not null)
        {
            var owner = await RequireUserAsync(existing.UserId, cancellationToken);
            RequireActive(owner, ErrorCodes.AccountNotActivated);
            await TryBackfillUnionIdAsync(existing, unionId, cancellationToken);

            return new WechatResolution(owner, IsNewUser: false, PhoneHandled: false);
        }

        // (2) The union id, which unifies one human across WeChat applications.
        if (unionId.Length > 0)
        {
            var unified = await identities.FindEarliestActiveWechatByUnionIdAsync(unionId, cancellationToken);

            if (unified is not null)
            {
                var owner = await RequireUserAsync(unified.UserId, cancellationToken);
                RequireActive(owner, ErrorCodes.AccountNotActivated);

                // One INSERT, so no explicit transaction: a single SaveChanges is already atomic,
                // and opening one here would only widen the window on a row nothing else contends
                // for.
                owner.Identities.Add(BuildProviderIdentity(identityType, provider, openId, unionId, details));
                await unitOfWork.SaveChangesAsync(cancellationToken);

                return new WechatResolution(owner, IsNewUser: false, PhoneHandled: false);
            }
        }

        // (3) The phone number the mini program handed over.
        if (phone.Length > 0)
        {
            var phoneIdentity = await identities.FindActiveAsync(
                IdentityTypes.Phone, HashOf(IdentityTypes.Phone, phone), cancellationToken);

            if (phoneIdentity is not null)
            {
                var owner = await RequireUserAsync(phoneIdentity.UserId, cancellationToken);
                RequireActive(owner, ErrorCodes.AccountNotActivated);

                var attached = BuildProviderIdentity(identityType, provider, openId, unionId, details);

                await unitOfWork.ExecuteInTransactionAsync(
                    async token =>
                    {
                        // Guarded because the unit of work replays this body on a transient
                        // PostgreSQL failure, and a second Add of the same instance would insert
                        // the identity twice.
                        if (!owner.Identities.Contains(attached))
                        {
                            owner.Identities.Add(attached);
                        }

                        await unitOfWork.SaveChangesAsync(token);
                    },
                    cancellationToken);

                return new WechatResolution(owner, IsNewUser: false, PhoneHandled: true);
            }
        }

        // (4) Nobody at all: a new account.
        var created = new User
        {
            // ACTIVE rather than PENDING: WeChat has just authenticated this person, so there is
            // nothing left for the account to be pending on.
            Status = UserStatuses.Active,
            Nickname = SocialProfileText.Nickname(null, null),
            CreatedAt = clock.UtcNow,
            UpdatedAt = clock.UtcNow,
        };

        created.Identities.Add(BuildProviderIdentity(identityType, provider, openId, unionId, details));

        if (phone.Length > 0)
        {
            created.Identities.Add(BuildIdentity(IdentityTypes.Phone, phone));
        }

        await unitOfWork.ExecuteInTransactionAsync(
            async token =>
            {
                users.Add(created);
                await unitOfWork.SaveChangesAsync(token);
            },
            cancellationToken);

        return new WechatResolution(created, IsNewUser: true, PhoneHandled: phone.Length > 0);
    }

    /// <summary>
    /// Write a union id onto an identity row that predates it - a web identity created before this
    /// app was bound to an Open Platform account, or one created before the binding existed at all.
    /// <para>
    /// Best effort by design. A failed backfill costs nothing today: the sign-in already succeeded
    /// on the openid, and the next one will try again. Letting it fail the request would turn a
    /// housekeeping write into an outage.
    /// </para>
    /// </summary>
    private async Task TryBackfillUnionIdAsync(
        UserIdentity identity,
        string unionId,
        CancellationToken cancellationToken)
    {
        if (unionId.Length == 0 || identity.ProviderUid == unionId)
        {
            return;
        }

        identity.ProviderUid = unionId;
        identity.ProviderDetails = ProviderDetailsFor(unionId).ToJson();
        identity.UpdatedAt = clock.UtcNow;

        try
        {
            identities.Update(identity);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        // Deliberately every exception rather than AppException alone. UnitOfWork translates only
        // the concurrency token and the unique violation into the application vocabulary; a check
        // constraint, a foreign key, a dropped connection or a raw NpgsqlException arrives as a
        // DbUpdateException and would escape a narrower filter. This write is housekeeping on a
        // flow that has ALREADY succeeded, so letting one through would turn a bookkeeping failure
        // into a failed sign-in - the thing "best effort" exists to rule out. Cancellation is
        // re-thrown: the caller went away, and reporting that as a mere failure would hide it.
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "Could not backfill the WeChat union id onto identity {IdentityId}; sign-in continues.",
                identity.Id);
        }
    }

    // =================================================================== LINE resolution

    /// <summary>
    /// Which account a LINE credential belongs to.
    /// <list type="number">
    /// <item><b>The LINE sub.</b> A returning user; the address is not even looked at.</item>
    /// <item>
    /// <b>The address on the token</b>, when a user here already owns it: a new LINE identity is
    /// attached to that account. <b>This is a silent merge - no consent screen.</b> It is preserved
    /// from the original and it is the weakest link in this slice: anyone who can obtain a LINE
    /// account asserting an address gains the account registered under it. LINE does verify the
    /// addresses it releases, which is what makes it defensible rather than indefensible, and the
    /// Firebase path shows what the stronger design looks like.
    /// </item>
    /// <item>Otherwise a new account, with the address bound alongside so the user can also sign in with it.</item>
    /// </list>
    /// </summary>
    private async Task<LineResolution> ResolveLineAsync(LineIdentity identity, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(identity.Sub))
        {
            throw new LineRejectedException("LINE returned no account identifier.");
        }

        var existing = await identities.FindActiveAsync(
            IdentityTypes.Line, HashOf(IdentityTypes.Line, identity.Sub), cancellationToken);

        if (existing is not null)
        {
            return new LineResolution(await RequireUserAsync(existing.UserId, cancellationToken), IsNewUser: false);
        }

        var email = identity.Email.Trim();
        var lineIdentity = BuildProviderIdentity(
            IdentityTypes.Line,
            SocialProviders.None,
            identity.Sub,
            // LINE has no cross-application identifier, so provider and provider_uid stay empty -
            // which also keeps these rows out of the (provider, provider_uid) unique index.
            providerUid: string.Empty,
            new ProviderDetails(
                EmailMasked: SocialProfileText.Mask(IdentityTypes.Email, email),
                Name: identity.Name));

        if (email.Length > 0)
        {
            var emailIdentity = await identities.FindActiveAsync(
                IdentityTypes.Email, HashOf(IdentityTypes.Email, email), cancellationToken);

            if (emailIdentity is not null)
            {
                var owner = await RequireUserAsync(emailIdentity.UserId, cancellationToken);

                logger.LogInformation(
                    "Linking a new LINE identity to account {UserId} matched on its email address.",
                    owner.Id);

                await unitOfWork.ExecuteInTransactionAsync(
                    async token =>
                    {
                        if (!owner.Identities.Contains(lineIdentity))
                        {
                            owner.Identities.Add(lineIdentity);
                        }

                        await unitOfWork.SaveChangesAsync(token);
                    },
                    cancellationToken);

                return new LineResolution(owner, IsNewUser: false);
            }
        }

        var created = new User
        {
            Status = UserStatuses.Active,
            Nickname = SocialProfileText.Nickname(identity.Name, email),
            Avatar = identity.Picture ?? string.Empty,
            CreatedAt = clock.UtcNow,
            UpdatedAt = clock.UtcNow,
        };

        created.Identities.Add(lineIdentity);

        if (email.Length > 0)
        {
            created.Identities.Add(BuildIdentity(IdentityTypes.Email, email));
        }

        await unitOfWork.ExecuteInTransactionAsync(
            async token =>
            {
                users.Add(created);
                await unitOfWork.SaveChangesAsync(token);
            },
            cancellationToken);

        return new LineResolution(created, IsNewUser: true);
    }

    // =================================================================== Firebase helpers

    /// <summary>
    /// The provider the client claimed, checked against the allow-list before anything else
    /// happens.
    /// <para>
    /// It runs before the token is verified because the check is free and the verification is a
    /// network round trip to Google, and because an allow-list refusal says nothing about whether
    /// the token was any good - which is the right amount to say.
    /// </para>
    /// </summary>
    private string RequireAllowedFirebaseProvider(string provider)
    {
        var normalized = provider?.Trim().ToLowerInvariant() ?? string.Empty;

        if (normalized.Length == 0)
        {
            throw new BadRequestException(
                ErrorCodes.FirebaseProviderRequired, "The Firebase sign-in provider is required.");
        }

        if (!_social.AllowedFirebaseProviders.Contains(normalized, StringComparer.Ordinal))
        {
            throw new BadRequestException(
                ErrorCodes.FirebaseProviderNotAllowed,
                "That Firebase sign-in provider is not enabled for this application.");
        }

        return normalized;
    }

    /// <summary>
    /// Verify the token, then check that its own <c>sign_in_provider</c> claim is the provider the
    /// client named.
    /// <para>
    /// The claim is authoritative and the client's field is not, so a disagreement is a refusal
    /// rather than a correction: a client that can steer which provider a token is filed under
    /// could file an Apple token as a Google one and land on the wrong identity row.
    /// </para>
    /// </summary>
    private async Task<FirebaseIdentity> VerifyFirebaseAsync(
        string idToken,
        string provider,
        CancellationToken cancellationToken)
    {
        var token = await firebase().VerifyIdTokenAsync(idToken, cancellationToken);

        if (!string.Equals(token.Provider, provider, StringComparison.Ordinal))
        {
            // The token's actual provider is named in the message rather than in a structured
            // detail member, because AppException carries no extension bag today. It is safe to
            // return: the caller is holding the token it came from.
            throw new UnauthorizedException(
                ErrorCodes.FirebaseProviderMismatch,
                $"The Firebase token was issued for '{token.Provider}', not '{provider}'.");
        }

        return token;
    }

    /// <summary>
    /// Hand back a signed proposal instead of a session. Deliberately carries no account data
    /// beyond the masked address: at this point the caller has proved control of a Firebase account
    /// and nothing more, and the account it is being offered may belong to somebody else entirely.
    /// </summary>
    private FirebaseSignInResponse ProposeFirebaseBinding(
        FirebaseIdentity token,
        string provider,
        UserIdentity emailIdentity,
        string email)
    {
        var masked = SocialProfileText.Mask(IdentityTypes.Email, email);

        logger.LogInformation(
            "A Firebase {Provider} sign-in matched the address of account {UserId}; asking for consent.",
            provider,
            emailIdentity.UserId);

        return new FirebaseSignInResponse
        {
            NeedsBindingConsent = true,
            FirebaseUid = token.Uid,
            Provider = provider,
            ProviderUid = token.ProviderUid,
            ExistingUserMaskedEmail = masked,
            BindingToken = bindingTokens.Issue(new FirebaseBindingProposal(
                token.Uid, provider, token.ProviderUid, emailIdentity.UserId, masked, token.Name)),
        };
    }

    private async Task<User> CreateFirebaseAccountAsync(
        FirebaseIdentity token,
        string provider,
        string email,
        CancellationToken cancellationToken)
    {
        var created = new User
        {
            Status = UserStatuses.Active,
            Nickname = SocialProfileText.Nickname(token.Name, email),
            Avatar = token.Picture,
            CreatedAt = clock.UtcNow,
            UpdatedAt = clock.UtcNow,
        };

        created.Identities.Add(BuildProviderIdentity(
            IdentityTypes.Firebase,
            provider,
            token.Uid,
            token.ProviderUid,
            new ProviderDetails(
                EmailMasked: SocialProfileText.Mask(IdentityTypes.Email, email),
                Name: token.Name)));

        if (email.Length > 0)
        {
            // Bound without a verification code, and that is the point of a federated sign-in: the
            // provider has just vouched for the address. An Apple relay address never reaches here
            // - FirebaseEmailRules already reduced it to empty.
            created.Identities.Add(BuildIdentity(IdentityTypes.Email, email));
        }

        await unitOfWork.ExecuteInTransactionAsync(
            async ct =>
            {
                users.Add(created);
                await unitOfWork.SaveChangesAsync(ct);
            },
            cancellationToken);

        return created;
    }

    private async Task<FirebaseSignInResponse> CompleteFirebaseSignInAsync(
        int userId,
        FirebaseIdentity token,
        string provider,
        bool isNewUser,
        CancellationToken cancellationToken) =>
        await CompleteFirebaseSignInAsync(
            await RequireUserAsync(userId, cancellationToken), token, provider, isNewUser, cancellationToken);

    private async Task<FirebaseSignInResponse> CompleteFirebaseSignInAsync(
        User user,
        FirebaseIdentity token,
        string provider,
        bool isNewUser,
        CancellationToken cancellationToken)
    {
        RequireActive(user, ErrorCodes.AccountNotActivated);
        await TouchLastLoginAsync(user, cancellationToken);

        return new FirebaseSignInResponse
        {
            NeedsBindingConsent = false,
            FirebaseUid = token.Uid,
            Provider = provider,
            ProviderUid = token.ProviderUid,
            Account = await DescribeAsync(user, isNewUser, cancellationToken),
        };
    }

    /// <summary>
    /// Insert one Firebase identity for an account, resolving every way it can already exist.
    /// <para>
    /// The two prechecks look redundant and are not: the first asks the question by uid, the second
    /// by the key the unique index actually enforces. A row bound under an <i>older</i> uid is
    /// invisible to the first and would collide in the INSERT - so the second both prevents that
    /// and gives the self-heal a place to happen.
    /// </para>
    /// <para>
    /// <b>The unique-violation catch is the third precheck, and the only one that is sound under
    /// concurrency.</b> Two confirmations racing can both pass the reads above; the loser lands in
    /// the catch, re-reads the winner's row, and folds the collision back into the same idempotent
    /// answer instead of showing a client a raw constraint violation for an operation that did in
    /// fact happen.
    /// </para>
    /// </summary>
    private async Task AttachFirebaseIdentityAsync(
        User user,
        string firebaseUid,
        string provider,
        string providerUid,
        ProviderDetails details,
        CancellationToken cancellationToken)
    {
        var byUid = await identities.FindActiveByIdentifierAndProviderAsync(
            IdentityTypes.Firebase, HashOf(IdentityTypes.Firebase, firebaseUid), provider, cancellationToken);

        if (byUid is not null)
        {
            RequireOwnedBy(byUid, user.Id, ErrorCodes.FirebaseIdentityAlreadyBound);
            return;
        }

        if (providerUid.Length > 0)
        {
            var byProviderKey = await identities.FindActiveByProviderAsync(
                IdentityTypes.Firebase, provider, providerUid, cancellationToken);

            if (byProviderKey is not null)
            {
                RequireOwnedBy(byProviderKey, user.Id, ErrorCodes.FirebaseIdentityAlreadyBound);
                await TryRepointFirebaseIdentifierAsync(byProviderKey, firebaseUid, cancellationToken);
                return;
            }
        }

        var identity = BuildProviderIdentity(
            IdentityTypes.Firebase, provider, firebaseUid, providerUid, details);

        try
        {
            user.Identities.Add(identity);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (ConflictException ex) when (ex.ErrorCode == ErrorCodes.Conflict && providerUid.Length > 0)
        {
            user.Identities.Remove(identity);

            var winner = await identities.FindActiveByProviderAsync(
                IdentityTypes.Firebase, provider, providerUid, cancellationToken);

            if (winner is null)
            {
                // The insert collided with something that is not there any more. Nothing sensible
                // is left to say, so the original conflict stands rather than being papered over.
                throw;
            }

            logger.LogInformation(
                ex,
                "A concurrent Firebase binding won the race for provider subject on account {UserId}; "
                + "resolving against the winning row.",
                user.Id);

            RequireOwnedBy(winner, user.Id, ErrorCodes.FirebaseIdentityAlreadyBound);
        }
        catch (ConflictException ex) when (ex.ErrorCode == ErrorCodes.Conflict)
        {
            // The same race, but for a token whose "identities" claim carried no subject, so there
            // is no provider key to re-read the winner by - only the (identity_type,
            // identifier_hash) index can have fired, and that says the uid is already bound
            // somewhere. Re-labelled rather than left to bubble: the untranslated message names the
            // PostgreSQL index, which tells the client nothing it can act on and tells an attacker
            // the shape of the schema.
            user.Identities.Remove(identity);

            throw new ConflictException(
                ErrorCodes.FirebaseIdentityAlreadyBound,
                "That Firebase account is already linked to another account.",
                ex);
        }
    }

    /// <summary>
    /// Re-point a Firebase identity at the uid Firebase is using today.
    /// <para>
    /// Uniqueness is keyed on (provider, provider subject) but lookups hash the uid, so once
    /// Firebase re-creates its user record the stored hash is stale and the fast path misses
    /// forever. This repairs it.
    /// </para>
    /// <para>
    /// <b>Best effort, and it must stay that way.</b> A failed repair costs one extra query on the
    /// next sign-in and nothing else; failing the caller's flow over it would turn a self-healing
    /// nicety into an outage for exactly the users whose rows are already unusual.
    /// </para>
    /// </summary>
    private async Task TryRepointFirebaseIdentifierAsync(
        UserIdentity identity,
        string firebaseUid,
        CancellationToken cancellationToken)
    {
        var hash = HashOf(IdentityTypes.Firebase, firebaseUid);
        if (identity.IdentifierHash == hash)
        {
            return;
        }

        identity.IdentifierHash = hash;
        identity.IdentifierCiphertext = protector.Encrypt(firebaseUid.Trim());
        identity.IdentifierKeyVersion = protector.KeyVersion;
        identity.UpdatedAt = clock.UtcNow;

        try
        {
            identities.Update(identity);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        // Deliberately every exception rather than AppException alone. UnitOfWork translates only
        // the concurrency token and the unique violation into the application vocabulary; a check
        // constraint, a foreign key, a dropped connection or a raw NpgsqlException arrives as a
        // DbUpdateException and would escape a narrower filter. This write is housekeeping on a
        // flow that has ALREADY succeeded, so letting one through would turn a bookkeeping failure
        // into a failed sign-in - the thing "best effort" exists to rule out. Cancellation is
        // re-thrown: the caller went away, and reporting that as a mere failure would hide it.
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "Could not re-point Firebase identity {IdentityId} at the current uid; sign-in continues.",
                identity.Id);
        }
    }

    // =================================================================== shared plumbing

    /// <summary>
    /// The shape of a bind: idempotent for the caller who already owns the identity, a conflict for
    /// everyone else, an insert otherwise.
    /// <para>
    /// <b>Answering 409 to the second caller is not an enumeration oracle</b>, which is worth
    /// stating because it looks like one. The caller has just proved control of the third-party
    /// account, so all it learns is that its own provider account is spoken for here - something it
    /// is entitled to know and cannot use to enumerate anyone else.
    /// </para>
    /// </summary>
    private async Task BindProviderIdentityAsync(
        int userId,
        string identityType,
        string provider,
        string subject,
        string providerUid,
        ProviderDetails details,
        string providerLabel,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new BadRequestException(
                ErrorCodes.BindFailed, $"{providerLabel} returned no account identifier.");
        }

        var existing = await identities.FindActiveAsync(
            identityType, HashOf(identityType, subject), cancellationToken);

        if (existing is not null)
        {
            RequireOwnedBy(existing, userId, ErrorCodes.IdentityAlreadyBound);
            return;
        }

        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "The account was not found.");

        var identity = BuildProviderIdentity(identityType, provider, subject, providerUid, details);

        try
        {
            user.Identities.Add(identity);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (ConflictException ex) when (ex.ErrorCode == ErrorCodes.Conflict)
        {
            // Somebody bound the same provider account between the read above and this insert. The
            // only unique index this statement can violate says exactly that, so the generic code
            // is replaced by the one the client can act on.
            user.Identities.Remove(identity);

            throw new ConflictException(
                ErrorCodes.IdentityAlreadyBound,
                $"That {providerLabel} account is already linked to another account.",
                ex);
        }
    }

    /// <summary>
    /// Wraps a bind-path code exchange so a provider refusal reports <c>BIND_FAILED</c> instead of
    /// the sign-in code the adapter defaults to. The adapter cannot know which flow it is serving,
    /// and the client's reaction differs: a failed sign-in restarts the sign-in, a failed bind
    /// returns to the settings screen.
    /// </summary>
    private static async Task<WechatCodeExchange> ExchangeForBindAsync(Func<Task<WechatCodeExchange>> exchange)
    {
        try
        {
            return await exchange();
        }
        catch (WechatRejectedException ex)
        {
            throw new BadRequestException(ErrorCodes.BindFailed, ex.Message, ex);
        }
    }

    /// <summary>
    /// Redeem the mini program's phone-number code, or give up quietly.
    /// <para>
    /// Everything here is best effort and the log level says so. WeChat's phone endpoint is the
    /// least reliable call in the slice - it needs a globally rate-limited access token that can be
    /// invalidated by any other service sharing the AppID - and a sign-in that failed because a
    /// convenience lookup failed would be an outage caused by a nicety.
    /// </para>
    /// </summary>
    private async Task<string> TryResolveMiniProgramPhoneAsync(string? phoneCode, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(phoneCode))
        {
            return string.Empty;
        }

        try
        {
            var phone = await wechatMini().GetPhoneNumberAsync(phoneCode, cancellationToken);
            return phone.Trim();
        }
        // Same reasoning as the database writes above: the phone number is a convenience the spec
        // calls best effort, and WeChat's phone endpoint is the least reliable call in the slice.
        // An exception shape the adapter did not anticipate must not cost the user their sign-in.
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex, "Could not resolve the WeChat mini-program phone number; continuing without it.");

            return string.Empty;
        }
    }

    /// <summary>
    /// Bind a resolved phone number onto an account that was found some other way.
    /// <para>
    /// <b>A number owned by somebody else is logged and skipped, never merged.</b> Once the account
    /// has been resolved - by openid or by union id - it is the answer, and moving a phone identity
    /// off another account to satisfy this one would silently take a login method away from a user
    /// who is not even part of this request.
    /// </para>
    /// </summary>
    private async Task TryAttachPhoneAsync(User user, string phone, CancellationToken cancellationToken)
    {
        try
        {
            var existing = await identities.FindActiveAsync(
                IdentityTypes.Phone, HashOf(IdentityTypes.Phone, phone), cancellationToken);

            if (existing is not null)
            {
                if (existing.UserId != user.Id)
                {
                    logger.LogWarning(
                        "The WeChat mini-program phone number is already an identity of account "
                        + "{OwnerId}; not merging it into the resolved account {UserId}.",
                        existing.UserId,
                        user.Id);
                }

                return;
            }

            // The account may already hold a DIFFERENT active phone number - somebody who
            // registered by phone and later signed in through the mini program on another SIM. The
            // spec relies on a per-user partial unique index to stop the second row; this repo's
            // user_identities has no such index (see the review notes), so the guard is here
            // instead. Two active PHONE identities would make "the account's phone number"
            // ambiguous for every flow that reads one, and quietly adding a second login
            // identifier the owner never asked for is worse than skipping a convenience.
            var alreadyHasPhone = await identities.ListActiveByUserAsync(user.Id, cancellationToken);

            if (alreadyHasPhone.Any(i => i.IdentityType == IdentityTypes.Phone))
            {
                logger.LogInformation(
                    "Account {UserId} already has an active phone identity; not adding the one WeChat "
                    + "reported for this mini-program sign-in.",
                    user.Id);

                return;
            }

            user.Identities.Add(BuildIdentity(IdentityTypes.Phone, phone));
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        // Deliberately every exception rather than AppException alone. UnitOfWork translates only
        // the concurrency token and the unique violation into the application vocabulary; a check
        // constraint, a foreign key, a dropped connection or a raw NpgsqlException arrives as a
        // DbUpdateException and would escape a narrower filter. This write is housekeeping on a
        // flow that has ALREADY succeeded, so letting one through would turn a bookkeeping failure
        // into a failed sign-in - the thing "best effort" exists to rule out. Cancellation is
        // re-thrown: the caller went away, and reporting that as a mere failure would hide it.
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex, "Could not bind the WeChat mini-program phone number to account {UserId}.", user.Id);
        }
    }

    /// <summary>
    /// Advance <c>last_login_at</c>. Best effort: the sign-in has already succeeded by the time
    /// this runs, and losing a timestamp is not worth turning into a failed login.
    /// </summary>
    private async Task TouchLastLoginAsync(User user, CancellationToken cancellationToken)
    {
        try
        {
            user.LastLoginAt = clock.UtcNow;
            user.UpdatedAt = clock.UtcNow;
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        // Deliberately every exception rather than AppException alone. UnitOfWork translates only
        // the concurrency token and the unique violation into the application vocabulary; a check
        // constraint, a foreign key, a dropped connection or a raw NpgsqlException arrives as a
        // DbUpdateException and would escape a narrower filter. This write is housekeeping on a
        // flow that has ALREADY succeeded, so letting one through would turn a bookkeeping failure
        // into a failed sign-in - the thing "best effort" exists to rule out. Cancellation is
        // re-thrown: the caller went away, and reporting that as a mere failure would hide it.
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Could not record the last sign-in time for account {UserId}.", user.Id);
        }
    }

    private async Task<SocialSignInResponse> DescribeAsync(
        User user,
        bool isNewUser,
        CancellationToken cancellationToken)
    {
        var all = await identities.ListActiveByUserAsync(user.Id, cancellationToken);

        return new SocialSignInResponse
        {
            UserId = user.Id,
            IsNewUser = isNewUser,
            NeedsBindPhone = !all.Any(i => i.IdentityType == IdentityTypes.Phone),
            Identities = [.. all.Select(Describe)],
        };
    }

    /// <summary>
    /// One identity as an anonymous caller may see it. The identifier is decrypted and then masked
    /// rather than returned in the clear - see <see cref="SocialProfileText.Mask"/>. A decryption
    /// failure degrades to an empty identifier instead of failing the sign-in, because a key
    /// rotation gone wrong must not lock people out of an account they can otherwise reach.
    /// </summary>
    private SocialIdentityResponse Describe(UserIdentity identity)
    {
        var identifier = string.Empty;

        if (identity.IdentifierCiphertext.Length > 0)
        {
            try
            {
                identifier = SocialProfileText.Mask(
                    identity.IdentityType, protector.Decrypt(identity.IdentifierCiphertext));
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException)
            {
                logger.LogWarning(
                    ex,
                    "Could not decrypt identity {IdentityId} (key version {KeyVersion}); "
                    + "reporting it without an identifier.",
                    identity.Id,
                    identity.IdentifierKeyVersion);
            }
        }

        return new SocialIdentityResponse
        {
            IdentityType = identity.IdentityType,
            Identifier = identifier,
            Provider = identity.Provider,
            ProviderUid = identity.ProviderUid,
            Status = identity.Status,
        };
    }

    private UserIdentity BuildProviderIdentity(
        string identityType,
        string provider,
        string subject,
        string providerUid,
        ProviderDetails details)
    {
        var identity = BuildIdentity(identityType, subject);

        identity.Provider = provider;
        identity.ProviderUid = providerUid;
        identity.ProviderDetails = details.ToJson();

        return identity;
    }

    private UserIdentity BuildIdentity(string identityType, string identifier)
    {
        var normalized = NormalizeIdentifier(identityType, identifier);
        var now = clock.UtcNow;

        return new UserIdentity
        {
            IdentityType = identityType,
            IdentifierHash = protector.Hash(normalized),
            IdentifierCiphertext = protector.Encrypt(normalized),
            IdentifierKeyVersion = protector.KeyVersion,
            Status = UserStatuses.Active,
            CreatedAt = now,
            UpdatedAt = now,
        };
    }

    private string HashOf(string identityType, string identifier) =>
        protector.Hash(NormalizeIdentifier(identityType, identifier));

    /// <summary>
    /// One spelling per identifier, and which spelling depends on what the identifier is.
    /// <para>
    /// Phone numbers and addresses go through <see cref="IdentifierNormalizer"/>, because a human
    /// types those and types them differently every time - and because a row written by this slice
    /// has to be found by registration and by the verification flows, which use exactly that
    /// function.
    /// </para>
    /// <para>
    /// <b>A provider subject is trimmed and nothing else.</b> An openid, a LINE sub and a Firebase
    /// uid are opaque, case-sensitive machine strings; lower-casing one or stripping its
    /// non-digits, which is what the phone rule would do, would produce a hash that matches a
    /// different account or no account at all.
    /// </para>
    /// </summary>
    private static string NormalizeIdentifier(string identityType, string identifier) =>
        identityType is IdentityTypes.Phone or IdentityTypes.Email
            ? IdentifierNormalizer.Normalize(identityType, identifier)
            : identifier.Trim();

    private static ProviderDetails ProviderDetailsFor(string unionId) =>
        unionId.Length == 0 ? ProviderDetails.Empty : new ProviderDetails(UnionId: unionId);

    private async Task<User> RequireUserAsync(int userId, CancellationToken cancellationToken) =>
        await users.FindByIdAsync(userId, cancellationToken)
        ?? throw new NotFoundException(ErrorCodes.UserNotFound, "The account was not found.");

    /// <summary>
    /// 403 rather than 401: the account exists, the credential was fine, and repeating the request
    /// with a fresher one changes nothing. Only an operator can lift this.
    /// </summary>
    private static void RequireActive(User user, string errorCode)
    {
        if (!user.IsActive())
        {
            throw new ForbiddenException(errorCode, "This account is not active.");
        }
    }

    private static void RequireOwnedBy(UserIdentity identity, int userId, string errorCode)
    {
        if (identity.UserId != userId)
        {
            throw new ConflictException(
                errorCode, "That provider account is already linked to another account.");
        }
    }

    /// <summary>
    /// The LINE flow re-labels a state failure as its own error code; see the remarks on
    /// <see cref="SignInWithLineAsync"/>.
    /// </summary>
    private string ReadLineNonce(string state)
    {
        try
        {
            return states.ReadNonce(state);
        }
        catch (BadRequestException ex) when (ex.ErrorCode == ErrorCodes.InvalidState)
        {
            throw new LineRejectedException("The sign-in state is invalid or has expired.", ex);
        }
    }

    private static string RequireSocialIdentityType(string identityType)
    {
        var normalized = identityType?.Trim().ToUpperInvariant() ?? string.Empty;

        return normalized is IdentityTypes.Wechat or IdentityTypes.WechatMini
            or IdentityTypes.Firebase or IdentityTypes.Line
            ? normalized
            // Phone, email and passkey are unbound through their own flows, which have preconditions
            // this one knows nothing about - a phone unbind, for instance, is what a phone change
            // goes through. Refusing is safer than half-implementing them here.
            : throw new BadRequestException(
                ErrorCodes.BadRequest,
                "Only WECHAT, WECHAT_MINI, FIREBASE and LINE identities are unbound through this endpoint.");
    }

    private sealed record WechatResolution(User User, bool IsNewUser, bool PhoneHandled);

    private sealed record LineResolution(User User, bool IsNewUser);
}
