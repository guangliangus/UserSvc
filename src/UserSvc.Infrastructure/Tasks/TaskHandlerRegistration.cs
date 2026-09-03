namespace UserSvc.Infrastructure.Tasks;

/// <summary>
/// One registered handler, as the runner needs to know it: which queue it serves and which type
/// implements it.
/// <para>
/// It exists so that <b>discovering the queues constructs nothing</b>. The queue name comes off the
/// handler TYPE (<c>ITaskHandler.QueueName</c> is static), and the handler itself is resolved only
/// when a task for it has actually been claimed, in that task's own scope. Discovering queues by
/// resolving every <c>ITaskHandler</c> instead would construct all of them at startup, so one
/// handler with a missing setting would throw during enumeration and take every other queue's
/// discovery down with it - the failure-isolation rule, in the place it is easiest to break.
/// </para>
/// </summary>
/// <param name="QueueName">The queue this handler serves.</param>
/// <param name="HandlerType">The concrete handler type, registered scoped and resolved per task.</param>
public sealed record TaskHandlerRegistration(string QueueName, Type HandlerType);
