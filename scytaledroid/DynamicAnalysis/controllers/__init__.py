"""Controllers for Dynamic Analysis CLI flows."""

__all__ = ["run_guided_dataset_run", "run_sandbox_dynamic_run"]


def __getattr__(name: str):
    if name == "run_guided_dataset_run":
        from .guided_run import run_guided_dataset_run

        return run_guided_dataset_run
    if name == "run_sandbox_dynamic_run":
        from .sandbox_run import run_sandbox_dynamic_run

        return run_sandbox_dynamic_run
    raise AttributeError(name)
