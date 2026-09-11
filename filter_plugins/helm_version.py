class FilterModule(object):
    def filters(self):
        return {
            "helm_chart_version_args": self.helm_chart_version_args,
        }

    def helm_chart_version_args(self, version):
        value = "" if version is None else str(version).strip()
        return f"--version {value}" if value else ""
