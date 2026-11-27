import importlib
import pathlib


class PluginLoader:

    def load_plugins(self):

        plugins = []

        plugin_folder = pathlib.Path("plugins")

        for file in plugin_folder.glob("*.py"):

            if file.stem == "base":
                continue

            module = importlib.import_module(
                f"plugins.{file.stem}"
            )

            for name in dir(module):

                obj = getattr(module, name)

                if hasattr(obj, "execute"):

                    try:
                        plugins.append(obj())
                    except:
                        pass

        return plugins