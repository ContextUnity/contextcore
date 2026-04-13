"""ContextUnity SDK — Project Bootstrap.

Single-function registration for ContextUnity projects.
Replaces ~500 lines of boilerplate in project apps.py + stream_executor.py.

Usage (Django):

    from contextunity.core.sdk.bootstrap import register_and_start
    from django.conf import settings
    import os
    import sys

    class ChatConfig(AppConfig):
        def ready(self):
            register_and_start(
                manifest_path=str(settings.BASE_DIR / "contextunity.project.yaml"),
                prompt_map={
                    "src/chat/prompts.py::PLANNER_PROMPT": PLANNER_PROMPT,
                    "src/chat/prompts.py::DB_SCHEMA": DB_SCHEMA,
                },
                tool_handler=my_tool_handler,
            )

After bootstrap, project code can use the cached identity via contextunity.core.sdk.identity.get_project_id().
"""

from .api import register_and_start
from .helpers import bootstrap_django, bootstrap_standalone

__all__ = ["register_and_start", "bootstrap_django", "bootstrap_standalone"]
