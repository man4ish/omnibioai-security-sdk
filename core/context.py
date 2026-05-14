from contextvars import ContextVar

user_ctx = ContextVar("user", default=None)
service_ctx = ContextVar("service", default=None)
trace_ctx = ContextVar("trace_id", default=None)


def set_user(user):
    user_ctx.set(user)


def get_user():
    return user_ctx.get()


def set_service(service):
    service_ctx.set(service)


def get_service():
    return service_ctx.get()


def set_trace(trace_id: str):
    trace_ctx.set(trace_id)


def get_trace():
    return trace_ctx.get()