# Build context = the repository root:
#   docker build -t user-svc .
# Adapted from the template's Dockerfile.hosts-single. Database schema is NOT baked or migrated
# here - db/*.sql is applied by hand first (decision 14, db/README.md).
ARG DOTNET_VERSION=10.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
ARG TARGETARCH
WORKDIR /src

COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/ src/

# publish restores with the right RID itself (a plain `dotnet restore` has no linux-$arch assets)
RUN arch=$([ "$TARGETARCH" = "amd64" ] && echo x64 || echo "$TARGETARCH") \
 && dotnet publish src/UserSvc.Api -c Release -a "$arch" -o /app/api

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS api
WORKDIR /app
COPY --from=build /app/api .
ENV ASPNETCORE_URLS=http://0.0.0.0:8080
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "UserSvc.Api.dll"]
