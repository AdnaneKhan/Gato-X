class ActionHandler:

    def _handle_checkout_action(self) -> None:
        """Handle 'actions/checkout' action."""
        with_params = self.step_data.get("with", {})
        ref_param = with_params.get("ref")

        if not isinstance(ref_param, str):
            self.is_checkout = False
        elif "path" in with_params:
            self.is_checkout = False
        elif "${{" in ref_param and "base" not in ref_param:
            self.metadata = ref_param
            self.is_checkout = True

    def _handle_setup_node_action(self) -> None:
        """Handle 'actions/setup-node' action."""
        with_params = self.step_data.get("with", {})
        if with_params.get("cache"):
            self.is_sink = True

    def _handle_setup_ruby_action(self) -> None:
        """Handle 'ruby/setup-ruby' action."""
        with_params = self.step_data.get("with", {})
        if with_params.get("bundler-cache"):
            self.is_sink = True

    def _handle_gradle_build_action(self) -> None:
        """Handle 'gradle/gradle-build-action' action."""
        with_params = self.step_data.get("with", {})
        if "arguments" in with_params:
            self.metadata = with_params

    def _handle_github_script_action(self) -> None:
        """Handle 'actions/github-script' action."""
        with_params = self.step_data.get("with", {})
        script_content = with_params.get("script")
        if script_content:
            self.contents = script_content
            if any(
                keyword in script_content
                for keyword in [
                    "getCollaboratorPermissionLevel",
                    "checkMembershipForUser",
                    "listMembersInOrg",
                ]
            ):
                self.is_gate = True
            self.is_script = True

    def _handle_actions_team_membership(self) -> None:
        """Handle 'actions-team-membership' action."""
        self.is_gate = True

    def _handle_get_user_teams_membership(self) -> None:
        """Handle 'get-user-teams-membership' action."""
        self.is_gate = True

    def _handle_permission_action(self) -> None:
        """Handle 'permission' action."""
        self.is_gate = True
