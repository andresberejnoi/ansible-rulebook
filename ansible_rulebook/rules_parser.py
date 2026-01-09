#  Copyright 2022 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import logging
import uuid
from typing import Any, Dict, List, Optional

import ansible_rulebook.rule_types as rt
from ansible_rulebook.collection import (
    EVENT_SOURCE_FILTER_OBJ_TYPE,
    EVENT_SOURCE_OBJ_TYPE,
    get_deprecation_info,
    get_redirect_info,
    get_tombstone_info,
    load_plugin_routing,
    log_deprecation_warning,
    split_collection_name,
)
from ansible_rulebook.condition_parser import (
    parse_condition as parse_condition_value,
)
from ansible_rulebook.conf import settings
from ansible_rulebook.util import substitute_variables

from .exception import (
    RulenameDuplicateException,
    RulenameEmptyException,
    RulesetNameDuplicateException,
    RulesetNameEmptyException,
    SourceFilterNotFoundException,
    SourcePluginNotFoundException,
)

LEGACY_FILTER_MAPPING = {
    "ansible.eda.dashes_to_underscores": (
        "ansible.builtin.dashes_to_underscores"
    ),
    "ansible.eda.json_filter": "eda.builtin.json_filter",
    "ansible.eda.normalize_keys": "eda.builtin.normalize_keys",
    "ansible.eda.insert_hosts_to_meta": "eda.builtin.insert_hosts_to_meta",
    "ansible.eda.noop": "eda.builtin.noop",
}

LEGACY_SOURCE_MAPPING = {
    "ansible.eda.pg_listener": "eda.builtin.pg_listener",
    "ansible.eda.generic": "eda.builtin.generic",
    "ansible.eda.range": "eda.builtin.range",
}

LOGGER = logging.getLogger(__name__)


def parse_hosts(hosts):
    if isinstance(hosts, str):
        return [hosts]
    elif isinstance(hosts, list):
        return hosts
    else:
        raise Exception(f"Unsupported hosts value {hosts}")


def parse_rule_sets(
    rule_sets: Dict, variables: Optional[Dict] = None
) -> List[rt.RuleSet]:
    rule_set_list = []
    ruleset_names = []
    for rule_set in rule_sets:
        name = rule_set.get("name")
        if name is None:
            raise RulesetNameEmptyException("Ruleset name not provided")

        name = name.strip()
        if name == "":
            raise RulesetNameEmptyException(
                "Ruleset name cannot be an empty string"
            )

        if name in ruleset_names:
            raise RulesetNameDuplicateException(
                f"Ruleset with name: {name} defined multiple times"
            )

        ruleset_names.append(name)

        if variables is None:
            variables = {}

        strategy = rule_set.get(
            "execution_strategy", settings.default_execution_strategy
        )
        if strategy == "sequential":
            execution_strategy = rt.ExecutionStrategy.SEQUENTIAL
        elif strategy == "parallel":
            execution_strategy = rt.ExecutionStrategy.PARALLEL

        rule_set_list.append(
            rt.RuleSet(
                name=name,
                hosts=parse_hosts(rule_set["hosts"]),
                sources=parse_event_sources(rule_set["sources"]),
                rules=parse_rules(rule_set.get("rules", {}), variables),
                execution_strategy=execution_strategy,
                gather_facts=rule_set.get("gather_facts", False),
                uuid=str(uuid.uuid4()),
                default_events_ttl=rule_set.get("default_events_ttl", None),
                match_multiple_rules=rule_set.get(
                    "match_multiple_rules", False
                ),
            )
        )
    return rule_set_list


def _apply_plugin_routing(
    plugin_name: str,
    obj_type: str,
    legacy_mapping: Dict,
    tombstone_exception: type,
) -> str:
    """Apply plugin routing (legacy, deprecation, tombstone, redirect).

    Follows ansible-core behavior:
    - Applies legacy mappings first
    - Follows redirect chains (not just single redirects)
    - Checks deprecation before tombstone for each plugin in chain
    - Detects redirect loops

    Args:
        plugin_name: The plugin name (source or filter)
        obj_type: Type of plugin ('event_source' or 'event_filter')
        legacy_mapping: Legacy mapping dict for this plugin type
        tombstone_exception: Exception to raise if tombstoned

    Returns:
        The final plugin name after applying routing rules

    Raises:
        tombstone_exception: If plugin is tombstoned
        ValueError: If redirect loop detected
    """
    # Check legacy mapping first
    if plugin_name in legacy_mapping:
        LOGGER.info(
            f"redirecting (type: {obj_type}) "
            f"{plugin_name} to {legacy_mapping[plugin_name]}"
        )
        return legacy_mapping[plugin_name]

    # Track redirect path to detect loops
    MAX_REDIRECT_CHAIN_LEN = 10
    redirect_chain = [plugin_name]
    current_name = plugin_name

    # Follow redirect chain
    jump_count = 0
    while jump_count < MAX_REDIRECT_CHAIN_LEN:
        # Load runtime plugin routing for current plugin
        plugin_routing = load_plugin_routing(current_name)
        if not plugin_routing:
            return current_name

        _, simple_plugin_name = split_collection_name(current_name)

        # First: Check deprecation
        deprecation_data = get_deprecation_info(
            plugin_routing, obj_type, simple_plugin_name
        )
        if deprecation_data:
            log_deprecation_warning(current_name, obj_type, deprecation_data)

        # Second: Check tombstone - if tombstoned, fail immediately
        tombstone_data = get_tombstone_info(
            plugin_routing, obj_type, simple_plugin_name
        )
        if tombstone_data:
            error_msg = (
                f"The {current_name} {obj_type} has been removed. "
                f"{tombstone_data.get('warning_text', '')}"
            )
            raise tombstone_exception(current_name, message=error_msg)

        # Third: Check for redirect
        redirect = get_redirect_info(
            plugin_routing, obj_type, simple_plugin_name
        )
        if redirect:
            # Check for redirect loop
            if redirect in redirect_chain:
                raise ValueError(
                    f"plugin redirect loop resolving {plugin_name} "
                    f"(path: {redirect_chain + [redirect]})"
                )

            LOGGER.info(
                f"redirecting (type: {obj_type}) "
                f"{current_name} to {redirect}"
            )
            redirect_chain.append(redirect)
            current_name = redirect
        else:
            return current_name

        jump_count += 1

    # This is raised when the while condition is no longer True
    else:
        error_msg = (
            f"Exceeded max allowed ({MAX_REDIRECT_CHAIN_LEN}) redirections"
        )
        # RuntimeError seems ok here, but maybe we need a different exception
        raise RuntimeError(error_msg)


def parse_event_sources(sources: Dict) -> List[rt.EventSource]:
    source_list = []
    for source in sources:
        name = source.pop("name", "")
        source_filters = []
        for source_filter in source.pop("filters", []):
            source_filters.append(parse_source_filter(source_filter))
        source_name = list(source.keys())[0]
        if source[source_name]:
            source_args = {k: v for k, v in source[source_name].items()}
        else:
            source_args = {}

        source_name = _apply_plugin_routing(
            source_name,
            EVENT_SOURCE_OBJ_TYPE,
            LEGACY_SOURCE_MAPPING,
            SourcePluginNotFoundException,
        )

        source_list.append(
            rt.EventSource(
                name=name or source_name,
                source_name=source_name,
                source_args=source_args,
                source_filters=source_filters,
            )
        )

    return source_list


def parse_source_filter(source_filter: Dict) -> rt.EventSourceFilter:

    source_filter_name = list(source_filter.keys())[0]
    source_filter_args = source_filter[source_filter_name]

    source_filter_name = _apply_plugin_routing(
        source_filter_name,
        EVENT_SOURCE_FILTER_OBJ_TYPE,
        LEGACY_FILTER_MAPPING,
        SourceFilterNotFoundException,
    )

    return rt.EventSourceFilter(source_filter_name, source_filter_args)


def parse_rules(rules: Dict, variables: Dict) -> List[rt.Rule]:
    rule_list = []
    rule_names = []
    if variables is None:
        variables = {}
    for rule in rules:
        name = rule.get("name")
        if name is None:
            raise RulenameEmptyException("Rule name not provided")

        name = substitute_variables(name, variables)
        if name == "":
            raise RulenameEmptyException("Rule name cannot be an empty string")

        if name in rule_names:
            raise RulenameDuplicateException(
                f"Rule with name {name} defined multiple times"
            )

        rule_names.append(name)
        if "throttle" in rule:
            throttle = rt.Throttle(
                once_within=rule["throttle"].get("once_within", None),
                once_after=rule["throttle"].get("once_after", None),
                group_by_attributes=rule["throttle"]["group_by_attributes"],
                accumulate_within=rule["throttle"].get(
                    "accumulate_within", None
                ),
                threshold=rule["throttle"].get("threshold", None),
            )
        else:
            throttle = None

        rule = rt.Rule(
            name=name,
            condition=parse_condition(rule["condition"]),
            actions=parse_actions(rule),
            enabled=rule.get("enabled", True),
            throttle=throttle,
            uuid=str(uuid.uuid4()),
        )
        if rule.enabled:
            rule_list.append(rule)

    return rule_list


def parse_actions(rule: Dict) -> List[rt.Action]:
    actions = []
    if "actions" in rule:
        for action in rule["actions"]:
            actions.append(parse_action(action))
    elif "action" in rule:
        actions.append(parse_action(rule["action"]))

    return actions


def parse_action(action: Dict) -> rt.Action:
    action_name = list(action.keys())[0]
    if action[action_name]:
        action_args = {k: v for k, v in action[action_name].items()}
    else:
        action_args = {}
    return rt.Action(action=action_name, action_args=action_args)


def parse_condition(condition: Any) -> rt.Condition:
    if isinstance(condition, str):
        return rt.Condition("all", [parse_condition_value(condition)])
    elif isinstance(condition, bool):
        return rt.Condition("all", [parse_condition_value(str(condition))])
    elif isinstance(condition, dict):
        timeout = condition.pop("timeout", None)
        keys = list(condition.keys())
        if len(condition) == 1 and keys[0] in ["any", "all", "not_all"]:
            when = keys[0]
            return rt.Condition(
                when,
                [parse_condition_value(str(c)) for c in condition[when]],
                timeout,
            )
        else:
            raise Exception(
                f"Condition should have one of any, all, not_all: {condition}"
            )

    else:
        raise Exception(f"Unsupported condition {condition}")
