#!/usr/bin/env python3

import argparse
import collections
import filecmp
import os
import re
import shutil
import tempfile

import yaml

from lib import (
    SpecAttr,
    SpecAttrSet,
    SpecEnumEntry,
    SpecEnumSet,
    SpecFamily,
    SpecOperation,
)

def c_upper(name):
    return name.upper().replace("-", "_")


def c_lower(name):
    return name.lower().replace("-", "_")


def limit_to_number(name):
    """
    Turn a string limit like u32-max or s64-min into its numerical value
    """
    if name[0] == "u" and name.endswith("-min"):
        return 0
    width = int(name[1:-4])
    if name[0] == "s":
        width -= 1
    value = (1 << width) - 1
    if name[0] == "s" and name.endswith("-min"):
        value = -value - 1
    return value


class BaseNlLib:
    def get_family_id(self):
        return "((struct ynl_sock*)ys)->family_id"


class Type(SpecAttr):
    def __init__(self, family, attr_set, attr, value):
        super().__init__(family, attr_set, attr, value)

        self.attr = attr
        self.attr_set = attr_set
        self.type = attr["type"]
        self.checks = attr.get("checks", {})

        self.request = False
        self.reply = False

        if "len" in attr:
            self.len = attr["len"]

        if "nested-attributes" in attr:
            self.nested_attrs = attr["nested-attributes"]
            if self.nested_attrs == family.name:
                self.nested_render_name = c_lower(f"{family.name}")
            else:
                self.nested_render_name = c_lower(f"{family.name}_{self.nested_attrs}")

            if self.nested_attrs in self.family.consts:
                self.nested_struct_type = self.nested_render_name + "_t"
            else:
                self.nested_struct_type = self.nested_render_name

        self.c_name = c_lower(self.name)
        if self.c_name in _C_KW:
            self.c_name += "_"

        # Added by resolve():
        self.enum_name = None
        delattr(self, "enum_name")

    def get_limit(self, limit, default=None):
        value = self.checks.get(limit, default)
        if value is None:
            return value
        elif value in self.family.consts:
            return c_upper(f"{self.family['name']}-{value}")
        if not isinstance(value, int):
            value = limit_to_number(value)
        return value

    def resolve(self):
        if "name-prefix" in self.attr:
            enum_name = f"{self.attr['name-prefix']}{self.name}"
        else:
            enum_name = f"{self.attr_set.name_prefix}{self.name}"
        self.enum_name = c_upper(enum_name)

    def is_multi_val(self):
        return None

    def is_scalar(self):
        return self.type in {"u8", "u16", "u32", "u64", "s32", "s64"}

    def is_recursive(self):
        return False

    def is_recursive_for_op(self, ri):
        return self.is_recursive() and not ri.op

    def presence_type(self):
        return "bit"

    def presence_member(self, space, type_filter):
        if self.presence_type() != type_filter:
            return

        if self.presence_type() == "bit":
            pfx = "__" if space == "user" else ""
            return f"{pfx}u32 {self.c_name}:1;"

        if self.presence_type() == "len":
            pfx = "__" if space == "user" else ""
            return f"{pfx}u32 {self.c_name}_len;"

    def _complex_member_type(self, ri):
        return None

    def arg_member(self, ri):
        member = self._complex_member_type(ri)
        if member:
            arg = [member + " *" + self.c_name]
            if self.presence_type() == "count":
                arg += ["unsigned int n_" + self.c_name]
            return arg
        raise Exception(f"Struct member not implemented for class type {self.type}")

    def struct_member(self, ri):
        member = self._complex_member_type(ri)
        if member:
            vec = True if self.is_multi_val() else False
            if self.is_recursive_for_op(ri):
                vec = True
            if vec:
                ri.cw.p(f"std::vector<{member}> {self.c_name};")
            else:
                ri.cw.p(f"std::optional<{member}> {self.c_name};")

            return
        members = self.arg_member(ri)
        for one in members:
            ri.cw.p(one + ";")

    def _attr_policy(self, policy):
        return "{ .type = " + policy + ", }"

    def attr_policy(self, cw):
        policy = c_upper("nla-" + self.attr["type"])

        spec = self._attr_policy(policy)
        cw.p(f"\t[{self.enum_name}] = {spec},")

    def _attr_typol(self):
        raise Exception(f"Type policy not implemented for class type {self.type}")

    def attr_typol(self, cw):
        typol = self._attr_typol()
        cw.p(f'arr[{self.enum_name}] = {"{"} .name = "{self.name}", {typol}{"}"};')

    def _attr_put_line(self, ri, var, line):
        if self.presence_type() == "flag":
            ri.cw.p(f"if ({var}.{self.c_name})")
        elif self.presence_type() == "bit":
            member = self._complex_member_type(ri)
            vec = True if self.is_multi_val() else False
            if self.is_recursive_for_op(ri):
                vec = True

            if vec:
                ri.cw.p(f"if ({var}.{self.c_name}.size() > 0)")
            else:
                ri.cw.p(f"if ({var}.{self.c_name}.has_value())")

        elif self.presence_type() == "len":
            ri.cw.p(f"if ({var}.{self.c_name}.size() > 0)")
        ri.cw.p(f"{line};")

    def _attr_put_simple(self, ri, var, put_type):
        if self.presence_type() == "len":
            line = f"ynl_attr_put_{put_type}(nlh, {self.enum_name}, {var}.{self.c_name}.data())"
        else:
            line = f"ynl_attr_put_{put_type}(nlh, {self.enum_name}, {var}.{self.c_name}.value())"
        self._attr_put_line(ri, var, line)

    def attr_put(self, ri, var):
        raise Exception(f"Put not implemented for class type {self.type}")

    def _attr_get(self, ri, var):
        raise Exception(f"Attr get not implemented for class type {self.type}")

    def attr_get(self, ri, var, first):
        lines, init_lines, local_vars = self._attr_get(ri, var)
        if type(lines) is str:
            lines = [lines]
        if type(init_lines) is str:
            init_lines = [init_lines]

        kw = "if" if first else "else if"
        ri.cw.block_start(line=f"{kw} (type == {self.enum_name})")
        if local_vars:
            for local in local_vars:
                ri.cw.p(local)
            ri.cw.nl()

        if not self.is_multi_val():
            ri.cw.p("if (ynl_attr_validate(yarg, attr))")
            ri.cw.p("return YNL_PARSE_CB_ERROR;")

        if init_lines:
            ri.cw.nl()
            for line in init_lines:
                ri.cw.p(line)

        for line in lines:
            ri.cw.p(line)
        ri.cw.block_end()
        return True


class TypeUnused(Type):
    def presence_type(self):
        return ""

    def arg_member(self, ri):
        return []

    def _attr_get(self, ri, var):
        return ["return YNL_PARSE_CB_ERROR;"], None, None

    def _attr_typol(self):
        return ".type = YNL_PT_REJECT, "

    def attr_policy(self, cw):
        pass

    def attr_put(self, ri, var):
        pass

    def attr_get(self, ri, var, first):
        pass


class TypePad(Type):
    def presence_type(self):
        return ""

    def arg_member(self, ri):
        return []

    def _attr_typol(self):
        return ".type = YNL_PT_IGNORE, "

    def attr_put(self, ri, var):
        pass

    def attr_get(self, ri, var, first):
        pass

    def attr_policy(self, cw):
        pass


class TypeScalar(Type):
    def __init__(self, family, attr_set, attr, value):
        super().__init__(family, attr_set, attr, value)

        self.byte_order_comment = ""
        if "byte-order" in attr:
            self.byte_order_comment = f" /* {attr['byte-order']} */"

        if "enum" in self.attr:
            enum = self.family.consts[self.attr["enum"]]
            low, high = enum.value_range()
            if "min" not in self.checks:
                if low != 0 or self.type[0] == "s":
                    self.checks["min"] = low
            if "max" not in self.checks:
                self.checks["max"] = high

        if "min" in self.checks and "max" in self.checks:
            if self.get_limit("min") > self.get_limit("max"):
                raise Exception(
                    f'Invalid limit for "{self.name}" min: {self.get_limit("min")} max: {self.get_limit("max")}'
                )
            self.checks["range"] = True

        low = min(self.get_limit("min", 0), self.get_limit("max", 0))
        high = max(self.get_limit("min", 0), self.get_limit("max", 0))
        if low < 0 and self.type[0] == "u":
            raise Exception(
                f'Invalid limit for "{self.name}" negative limit for unsigned type'
            )
        if low < -32768 or high > 32767:
            self.checks["full-range"] = True

        # Added by resolve():
        self.is_bitfield = None
        delattr(self, "is_bitfield")
        self.type_name = None
        delattr(self, "type_name")

    def resolve(self):
        self.resolve_up(super())

        if "enum-as-flags" in self.attr and self.attr["enum-as-flags"]:
            self.is_bitfield = True
        elif "enum" in self.attr:
            self.is_bitfield = self.family.consts[self.attr["enum"]]["type"] == "flags"
        else:
            self.is_bitfield = False

        if not self.is_bitfield and "enum" in self.attr:
            self.type_name = self.family.consts[self.attr["enum"]].user_type
        elif self.is_auto_scalar:
            self.type_name = "__" + self.type[0] + "64"
        else:
            self.type_name = "__" + self.type

    def _attr_policy(self, policy):
        if "flags-mask" in self.checks or self.is_bitfield:
            if self.is_bitfield:
                enum = self.family.consts[self.attr["enum"]]
                mask = enum.get_mask(as_flags=True)
            else:
                flags = self.family.consts[self.checks["flags-mask"]]
                flag_cnt = len(flags["entries"])
                mask = (1 << flag_cnt) - 1
            return f"NLA_POLICY_MASK({policy}, 0x{mask:x})"
        elif "full-range" in self.checks:
            return f"NLA_POLICY_FULL_RANGE({policy}, &{c_lower(self.enum_name)}_range)"
        elif "range" in self.checks:
            return f"NLA_POLICY_RANGE({policy}, {self.get_limit('min')}, {self.get_limit('max')})"
        elif "min" in self.checks:
            return f"NLA_POLICY_MIN({policy}, {self.get_limit('min')})"
        elif "max" in self.checks:
            return f"NLA_POLICY_MAX({policy}, {self.get_limit('max')})"
        return super()._attr_policy(policy)

    def _attr_typol(self):
        return f".type = YNL_PT_U{c_upper(self.type[1:])}, "

    def arg_member(self, ri):
        return [
            f"std::optional<{self.type_name}> {self.c_name}{self.byte_order_comment}"
        ]

    def attr_put(self, ri, var):
        self._attr_put_simple(ri, var, self.type)

    def _attr_get(self, ri, var):
        return (
            f"{var}->{self.c_name} = ({self.type_name})ynl_attr_get_{self.type}(attr);",
            None,
            None,
        )

    def _setter_lines(self, ri, member, presence):
        return [f"{member} = {self.c_name};"]


class TypeFlag(Type):
    def arg_member(self, ri):
        return [f"bool {self.c_name}"]

    def presence_type(self):
        return "flag"

    def struct_member(self, ri):
        ri.cw.p(f"bool {self.c_name}{{}};")

    def _attr_typol(self):
        return ".type = YNL_PT_FLAG, "

    def attr_put(self, ri, var):
        self._attr_put_line(ri, var, f"ynl_attr_put(nlh, {self.enum_name}, NULL, 0)")

    def _attr_get(self, ri, var):
        return [], None, None

    def _setter_lines(self, ri, member, presence):
        return []


class TypeString(Type):
    def arg_member(self, ri):
        return [f"std::string {self.c_name}"]

    def presence_type(self):
        return "len"

    def struct_member(self, ri):
        ri.cw.p(f"std::string {self.c_name};")

    def _attr_typol(self):
        return f".type = YNL_PT_NUL_STR, "

    def _attr_policy(self, policy):
        if "exact-len" in self.checks:
            mem = "NLA_POLICY_EXACT_LEN(" + str(self.get_limit("exact-len")) + ")"
        else:
            mem = "{ .type = " + policy
            if "max-len" in self.checks:
                mem += ", .len = " + str(self.get_limit("max-len"))
            mem += ", }"
        return mem

    def attr_policy(self, cw):
        if self.checks.get("unterminated-ok", False):
            policy = "NLA_STRING"
        else:
            policy = "NLA_NUL_STRING"

        spec = self._attr_policy(policy)
        cw.p(f"\t[{self.enum_name}] = {spec},")

    def attr_put(self, ri, var):
        self._attr_put_simple(ri, var, "str")

    def _attr_get(self, ri, var):
        return (
            [
                f"{var}->{self.c_name}.assign(ynl_attr_get_str(attr));",
            ],
            None,
            None,
        )

    def _setter_lines(self, ri, member, presence):
        return [
            f"{member} = {self.c_name};",
        ]


class TypeBinary(Type):
    def arg_member(self, ri):
        return [f"const void *{self.c_name}", "size_t len"]

    def presence_type(self):
        return "len"

    def struct_member(self, ri):
        ri.cw.p(f"std::vector<__u8> {self.c_name};")

    def _attr_typol(self):
        return f".type = YNL_PT_BINARY,"

    def _attr_policy(self, policy):
        if "exact-len" in self.checks:
            mem = "NLA_POLICY_EXACT_LEN(" + str(self.get_limit("exact-len")) + ")"
        else:
            mem = "{ "
            if len(self.checks) == 1 and "min-len" in self.checks:
                mem += ".len = " + str(self.get_limit("min-len"))
            elif len(self.checks) == 0:
                mem += ".type = NLA_BINARY"
            else:
                raise Exception(
                    "One or more of binary type checks not implemented, yet"
                )
            mem += ", }"
        return mem

    def attr_put(self, ri, var):
        self._attr_put_line(
            ri,
            var,
            f"ynl_attr_put(nlh, {self.enum_name}, "
            + f"{var}.{self.c_name}.data(), {var}.{self.c_name}.size())",
        )

    def _attr_get(self, ri, var):
        return (
            [
                f"unsigned int len = ynl_attr_data_len(attr);",
                f"__u8 *data = (__u8*)ynl_attr_data(attr);",
                f"{var}->{self.c_name}.assign(data, data + len);",
            ],
            None,
            None,
        )

    def _setter_lines(self, ri, member, presence):
        return [
            f"free({member});",
            f"{presence}_len = len;",
            f"{member} = malloc({presence}_len);",
            f"memcpy({member}, {self.c_name}, {presence}_len);",
        ]


class TypeBitfield32(Type):
    def _complex_member_type(self, ri):
        return "struct nla_bitfield32"

    def _attr_typol(self):
        return f".type = YNL_PT_BITFIELD32, "

    def _attr_policy(self, policy):
        if not "enum" in self.attr:
            raise Exception("Enum required for bitfield32 attr")
        enum = self.family.consts[self.attr["enum"]]
        mask = enum.get_mask(as_flags=True)
        return f"NLA_POLICY_BITFIELD32({mask})"

    def attr_put(self, ri, var):
        line = f"ynl_attr_put(nlh, {self.enum_name}, &(*{var}.{self.c_name}), sizeof(struct nla_bitfield32))"
        self._attr_put_line(ri, var, line)

    def _attr_get(self, ri, var):
        return (
            f"memcpy(&{var}->{self.c_name}, ynl_attr_data(attr), sizeof(struct nla_bitfield32));",
            None,
            None,
        )

    def _setter_lines(self, ri, member, presence):
        return [f"memcpy(&{member}, {self.c_name}, sizeof(struct nla_bitfield32));"]


class TypeNest(Type):
    def is_recursive(self):
        return self.family.pure_nested_structs[self.nested_attrs].recursive

    def _complex_member_type(self, ri):
        return self.nested_struct_type

    def _attr_typol(self):
        return f".type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, "

    def _attr_policy(self, policy):
        return "NLA_POLICY_NESTED(" + self.nested_render_name + "_nl_policy)"

    def attr_put(self, ri, var):
        # at = "" if self.is_recursive_for_op(ri) else "&"
        at = ""
        self._attr_put_line(
            ri,
            var,
            f"{self.nested_render_name}_put(nlh, "
            + f"{self.enum_name}, {at}{var}.{self.c_name}.value())",
        )

    def _attr_get(self, ri, var):
        get_lines = [
            f"if ({self.nested_render_name}_parse(&parg, attr))",
            "return YNL_PARSE_CB_ERROR;",
        ]
        init_lines = [
            f"parg.rsp_policy = &{self.nested_render_name}_nest;",
            f"parg.data = &{var}->{self.c_name};",
        ]
        return get_lines, init_lines, None


class TypeMultiAttr(Type):
    def __init__(self, family, attr_set, attr, value, base_type):
        super().__init__(family, attr_set, attr, value)

        self.base_type = base_type

    def is_multi_val(self):
        return True

    def presence_type(self):
        return "count"

    def _complex_member_type(self, ri):
        if "type" not in self.attr or self.attr["type"] == "nest":
            return self.nested_struct_type
        elif self.attr["type"] in scalars:
            scalar_pfx = "__" if ri.ku_space == "user" else ""
            return scalar_pfx + self.attr["type"]
        else:
            raise Exception(f"Sub-type {self.attr['type']} not supported yet")

    def _attr_policy(self, policy):
        return self.base_type._attr_policy(policy)

    def _attr_typol(self):
        return self.base_type._attr_typol()

    def _attr_get(self, ri, var):
        return f"n_{self.c_name}++;", None, None

    def attr_put(self, ri, var):
        if self.attr["type"] in scalars:
            put_type = self.type
            ri.cw.p(f"for (unsigned int i = 0; i < {var}.{self.c_name}.size(); i++)")
            ri.cw.p(
                f"ynl_attr_put_{put_type}(nlh, {self.enum_name}, {var}.{self.c_name}[i]);"
            )
        elif "type" not in self.attr or self.attr["type"] == "nest":
            ri.cw.p(f"for (unsigned int i = 0; i < {var}.{self.c_name}.size(); i++)")
            self._attr_put_line(
                ri,
                var,
                f"{self.nested_render_name}_put(nlh, "
                + f"{self.enum_name}, {var}.{self.c_name}[i])",
            )
        else:
            raise Exception(
                f"Put of MultiAttr sub-type {self.attr['type']} not supported yet"
            )

    def _setter_lines(self, ri, member, presence):
        # For multi-attr we have a count, not presence, hack up the presence
        presence = (
            presence[: -(len("_present.") + len(self.c_name))] + "n_" + self.c_name
        )
        return [
            f"free({member});",
            f"{member} = {self.c_name};",
            f"{presence} = n_{self.c_name};",
        ]


class TypeArrayNest(Type):
    def is_multi_val(self):
        return True

    def presence_type(self):
        return "count"

    def _complex_member_type(self, ri):
        if "sub-type" not in self.attr or self.attr["sub-type"] == "nest":
            return self.nested_struct_type
        elif self.attr["sub-type"] in scalars:
            scalar_pfx = "__" if ri.ku_space == "user" else ""
            return scalar_pfx + self.attr["sub-type"]
        else:
            raise Exception(f"Sub-type {self.attr['sub-type']} not supported yet")

    def _attr_typol(self):
        return f".type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, "

    def _attr_get(self, ri, var):
        local_vars = ["const struct nlattr *attr2;"]
        get_lines = [
            f"attr_{self.c_name} = attr;",
            "ynl_attr_for_each_nested(attr2, attr)",
            f"\t{var}->n_{self.c_name}++;",
        ]
        return get_lines, None, local_vars


class TypeNestTypeValue(Type):
    def _complex_member_type(self, ri):
        return self.nested_struct_type

    def _attr_typol(self):
        return f".type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, "

    def _attr_get(self, ri, var):
        prev = "attr"
        tv_args = ""
        get_lines = []
        local_vars = []
        init_lines = [
            f"parg.rsp_policy = &{self.nested_render_name}_nest;",
            f"parg.data = &{var}->{self.c_name};",
        ]
        if "type-value" in self.attr:
            tv_names = [c_lower(x) for x in self.attr["type-value"]]
            local_vars += [f'const struct nlattr *attr_{", *attr_".join(tv_names)};']
            local_vars += [f'__u32 {", ".join(tv_names)};']
            for level in self.attr["type-value"]:
                level = c_lower(level)
                get_lines += [f"attr_{level} = ynl_attr_data({prev});"]
                get_lines += [f"{level} = ynl_attr_type(attr_{level});"]
                prev = "attr_" + level

            tv_args = f", {', '.join(tv_names)}"

        get_lines += [f"{self.nested_render_name}_parse(&parg, {prev}{tv_args});"]
        return get_lines, init_lines, local_vars


class Struct:
    def __init__(self, family, space_name, type_list=None, inherited=None):
        self.family = family
        self.space_name = space_name
        self.attr_set = family.attr_sets[space_name]
        # Use list to catch comparisons with empty sets
        self._inherited = inherited if inherited is not None else []
        self.inherited = []

        self.nested = type_list is None
        if family.name == c_lower(space_name):
            self.render_name = c_lower(family.name)
        else:
            self.render_name = c_lower(family.name + "-" + space_name)
        self.struct_name = self.render_name

        if self.nested and space_name in family.consts:
            self.struct_name += "_t"
            self.ptr_name = self.render_name + "_t *"
            self.ref_name = self.render_name + "_t& "
        else:
            self.ptr_name = self.render_name + " *"
            self.ref_name = self.render_name + "& "
        # All attr sets this one contains, directly or multiple levels down
        self.child_nests = set()

        self.request = False
        self.reply = False
        self.recursive = False

        self.attr_list = []
        self.attrs = dict()
        if type_list is not None:
            for t in type_list:
                self.attr_list.append(
                    (t, self.attr_set[t]),
                )
        else:
            for t in self.attr_set:
                self.attr_list.append(
                    (t, self.attr_set[t]),
                )

        max_val = 0
        self.attr_max_val = None
        for name, attr in self.attr_list:
            if attr.value >= max_val:
                max_val = attr.value
                self.attr_max_val = attr
            self.attrs[name] = attr

    def __iter__(self):
        yield from self.attrs

    def __getitem__(self, key):
        return self.attrs[key]

    def member_list(self):
        return self.attr_list

    def set_inherited(self, new_inherited):
        if self._inherited != new_inherited:
            raise Exception("Inheriting different members not supported")
        self.inherited = [c_lower(x) for x in sorted(self._inherited)]


class EnumEntry(SpecEnumEntry):
    def __init__(self, enum_set, yaml, prev, value_start):
        super().__init__(enum_set, yaml, prev, value_start)

        if prev:
            self.value_change = self.value != prev.value + 1
        else:
            self.value_change = self.value != 0
        self.value_change = self.value_change or self.enum_set["type"] == "flags"

        # Added by resolve:
        self.c_name = None
        delattr(self, "c_name")

    def resolve(self):
        self.resolve_up(super())

        self.c_name = c_upper(self.enum_set.value_pfx + self.name)


class EnumSet(SpecEnumSet):
    def __init__(self, family, yaml):
        self.render_name = c_lower(family.name + "-" + yaml["name"])

        if "enum-name" in yaml:
            if yaml["enum-name"]:
                self.enum_name = c_lower(yaml["enum-name"])
                self.user_type = self.enum_name
            else:
                self.enum_name = None
        else:
            self.enum_name = self.render_name

        if self.enum_name:
            self.user_type = self.enum_name
        else:
            self.user_type = "int"

        self.value_pfx = yaml.get("name-prefix", f"{family.name}-{yaml['name']}-")

        super().__init__(family, yaml)

    def new_entry(self, entry, prev_entry, value_start):
        return EnumEntry(self, entry, prev_entry, value_start)

    def value_range(self):
        low = min([x.value for x in self.entries.values()])
        high = max([x.value for x in self.entries.values()])

        if high - low + 1 != len(self.entries):
            raise Exception("Can't get value range for a noncontiguous enum")

        return low, high


class AttrSet(SpecAttrSet):
    def __init__(self, family, yaml):
        super().__init__(family, yaml)

        if self.subset_of is None:
            if "name-prefix" in yaml:
                pfx = yaml["name-prefix"]
            elif self.name == family.name:
                pfx = family.name + "-a-"
            else:
                pfx = f"{family.name}-a-{self.name}-"
            self.name_prefix = c_upper(pfx)
            self.max_name = c_upper(
                self.yaml.get("attr-max-name", f"{self.name_prefix}max")
            )
            self.cnt_name = c_upper(
                self.yaml.get("attr-cnt-name", f"__{self.name_prefix}max")
            )
        else:
            self.name_prefix = family.attr_sets[self.subset_of].name_prefix
            self.max_name = family.attr_sets[self.subset_of].max_name
            self.cnt_name = family.attr_sets[self.subset_of].cnt_name

        # Added by resolve:
        self.c_name = None
        delattr(self, "c_name")

    def resolve(self):
        self.c_name = c_lower(self.name)
        if self.c_name in _C_KW:
            self.c_name += "_"
        if self.c_name == self.family.c_name:
            self.c_name = ""

    def new_attr(self, elem, value):
        if elem["type"] in scalars:
            t = TypeScalar(self.family, self, elem, value)
        elif elem["type"] == "unused":
            t = TypeUnused(self.family, self, elem, value)
        elif elem["type"] == "pad":
            t = TypePad(self.family, self, elem, value)
        elif elem["type"] == "flag":
            t = TypeFlag(self.family, self, elem, value)
        elif elem["type"] == "string":
            t = TypeString(self.family, self, elem, value)
        elif elem["type"] == "binary":
            t = TypeBinary(self.family, self, elem, value)
        elif elem["type"] == "bitfield32":
            t = TypeBitfield32(self.family, self, elem, value)
        elif elem["type"] == "nest":
            t = TypeNest(self.family, self, elem, value)
        elif elem["type"] == "indexed-array" and "sub-type" in elem:
            if elem["sub-type"] == "nest":
                t = TypeArrayNest(self.family, self, elem, value)
            else:
                raise Exception(f'new_attr: unsupported sub-type {elem["sub-type"]}')
        elif elem["type"] == "nest-type-value":
            t = TypeNestTypeValue(self.family, self, elem, value)
        else:
            raise Exception(f"No typed class for type {elem['type']}")

        if "multi-attr" in elem and elem["multi-attr"]:
            t = TypeMultiAttr(self.family, self, elem, value, t)

        return t


class Operation(SpecOperation):
    def __init__(self, family, yaml, req_value, rsp_value):
        super().__init__(family, yaml, req_value, rsp_value)

        self.render_name = c_lower(family.name + "_" + self.name)

        self.dual_policy = ("do" in yaml and "request" in yaml["do"]) and (
            "dump" in yaml and "request" in yaml["dump"]
        )

        self.has_ntf = False

        # Added by resolve:
        self.enum_name = None
        delattr(self, "enum_name")

    def resolve(self):
        self.resolve_up(super())

        if not self.is_async:
            self.enum_name = self.family.op_prefix + c_upper(self.name)
        else:
            self.enum_name = self.family.async_op_prefix + c_upper(self.name)

    def mark_has_ntf(self):
        self.has_ntf = True


class Family(SpecFamily):
    def __init__(self, file_name, exclude_ops):
        # Added by resolve:
        self.c_name = None
        delattr(self, "c_name")
        self.op_prefix = None
        delattr(self, "op_prefix")
        self.async_op_prefix = None
        delattr(self, "async_op_prefix")
        self.mcgrps = None
        delattr(self, "mcgrps")
        self.consts = None
        delattr(self, "consts")
        self.hooks = None
        delattr(self, "hooks")

        super().__init__(file_name, exclude_ops=exclude_ops)

        self.fam_key = c_upper(
            self.yaml.get("c-family-name", self.yaml["name"] + "_FAMILY_NAME")
        )
        self.ver_key = c_upper(
            self.yaml.get("c-version-name", self.yaml["name"] + "_FAMILY_VERSION")
        )

        if "definitions" not in self.yaml:
            self.yaml["definitions"] = []

        if "uapi-header" in self.yaml:
            self.uapi_header = self.yaml["uapi-header"]
        else:
            self.uapi_header = f"linux/{c_lower(self.name)}.h"
        if self.uapi_header.startswith("linux/") and self.uapi_header.endswith(".h"):
            self.uapi_header_name = self.uapi_header[6:-2]
        else:
            self.uapi_header_name = self.name

    def resolve(self):
        self.resolve_up(super())

        if self.yaml.get("protocol", "genetlink") not in {
            "genetlink",
            "genetlink-c",
            "genetlink-legacy",
        }:
            raise Exception("Codegen only supported for genetlink")

        self.c_name = c_lower(self.name)
        if "name-prefix" in self.yaml["operations"]:
            self.op_prefix = c_upper(self.yaml["operations"]["name-prefix"])
        else:
            self.op_prefix = c_upper(self.yaml["name"] + "-cmd-")
        if "async-prefix" in self.yaml["operations"]:
            self.async_op_prefix = c_upper(self.yaml["operations"]["async-prefix"])
        else:
            self.async_op_prefix = self.op_prefix

        self.mcgrps = self.yaml.get("mcast-groups", {"list": []})

        self.hooks = dict()
        for when in ["pre", "post"]:
            self.hooks[when] = dict()
            for op_mode in ["do", "dump"]:
                self.hooks[when][op_mode] = dict()
                self.hooks[when][op_mode]["set"] = set()
                self.hooks[when][op_mode]["list"] = []

        # dict space-name -> 'request': set(attrs), 'reply': set(attrs)
        self.root_sets = dict()
        # dict space-name -> set('request', 'reply')
        self.pure_nested_structs = dict()

        self._mark_notify()
        self._mock_up_events()

        self._load_root_sets()
        self._load_nested_sets()
        self._load_attr_use()
        self._load_hooks()

        self.kernel_policy = self.yaml.get("kernel-policy", "split")
        if self.kernel_policy == "global":
            self._load_global_policy()

    def new_enum(self, elem):
        return EnumSet(self, elem)

    def new_attr_set(self, elem):
        return AttrSet(self, elem)

    def new_operation(self, elem, req_value, rsp_value):
        return Operation(self, elem, req_value, rsp_value)

    def _mark_notify(self):
        for op in self.msgs.values():
            if "notify" in op:
                self.ops[op["notify"]].mark_has_ntf()

    # Fake a 'do' equivalent of all events, so that we can render their response parsing
    def _mock_up_events(self):
        for op in self.yaml["operations"]["list"]:
            if "event" in op:
                op["do"] = {"reply": {"attributes": op["event"]["attributes"]}}

    def _load_root_sets(self):
        for op_name, op in self.msgs.items():
            if "attribute-set" not in op:
                continue

            req_attrs = set()
            rsp_attrs = set()
            for op_mode in ["do", "dump"]:
                if op_mode in op and "request" in op[op_mode]:
                    req_attrs.update(set(op[op_mode]["request"]["attributes"]))
                if op_mode in op and "reply" in op[op_mode]:
                    rsp_attrs.update(set(op[op_mode]["reply"]["attributes"]))
            if "event" in op:
                rsp_attrs.update(set(op["event"]["attributes"]))

            if op["attribute-set"] not in self.root_sets:
                self.root_sets[op["attribute-set"]] = {
                    "request": req_attrs,
                    "reply": rsp_attrs,
                }
            else:
                self.root_sets[op["attribute-set"]]["request"].update(req_attrs)
                self.root_sets[op["attribute-set"]]["reply"].update(rsp_attrs)

    def _sort_pure_types(self):
        # Try to reorder according to dependencies
        pns_key_list = list(self.pure_nested_structs.keys())
        pns_key_seen = set()
        rounds = len(pns_key_list) ** 2  # it's basically bubble sort
        for _ in range(rounds):
            if len(pns_key_list) == 0:
                break
            name = pns_key_list.pop(0)
            finished = True
            for _, spec in self.attr_sets[name].items():
                if "nested-attributes" in spec:
                    nested = spec["nested-attributes"]
                    # If the unknown nest we hit is recursive it's fine, it'll be a pointer
                    if self.pure_nested_structs[nested].recursive:
                        continue
                    if nested not in pns_key_seen:
                        # Dicts are sorted, this will make struct last
                        struct = self.pure_nested_structs.pop(name)
                        self.pure_nested_structs[name] = struct
                        finished = False
                        break
            if finished:
                pns_key_seen.add(name)
            else:
                pns_key_list.append(name)

    def _load_nested_sets(self):
        attr_set_queue = list(self.root_sets.keys())
        attr_set_seen = set(self.root_sets.keys())

        while len(attr_set_queue):
            a_set = attr_set_queue.pop(0)
            for attr, spec in self.attr_sets[a_set].items():
                if "nested-attributes" not in spec:
                    continue

                nested = spec["nested-attributes"]
                if nested not in attr_set_seen:
                    attr_set_queue.append(nested)
                    attr_set_seen.add(nested)

                inherit = set()
                if nested not in self.root_sets:
                    if nested not in self.pure_nested_structs:
                        self.pure_nested_structs[nested] = Struct(
                            self, nested, inherited=inherit
                        )
                else:
                    raise Exception(
                        f"Using attr set as root and nested not supported - {nested}"
                    )

                if "type-value" in spec:
                    if nested in self.root_sets:
                        raise Exception(
                            "Inheriting members to a space used as root not supported"
                        )
                    inherit.update(set(spec["type-value"]))
                elif spec["type"] == "indexed-array":
                    inherit.add("idx")
                self.pure_nested_structs[nested].set_inherited(inherit)

        for root_set, rs_members in self.root_sets.items():
            for attr, spec in self.attr_sets[root_set].items():
                if "nested-attributes" in spec:
                    nested = spec["nested-attributes"]
                    if attr in rs_members["request"]:
                        self.pure_nested_structs[nested].request = True
                    if attr in rs_members["reply"]:
                        self.pure_nested_structs[nested].reply = True

        self._sort_pure_types()

        # Propagate the request / reply / recursive
        for attr_set, struct in reversed(self.pure_nested_structs.items()):
            for _, spec in self.attr_sets[attr_set].items():
                if "nested-attributes" in spec:
                    child_name = spec["nested-attributes"]
                    struct.child_nests.add(child_name)
                    child = self.pure_nested_structs.get(child_name)
                    if child:
                        if not child.recursive:
                            struct.child_nests.update(child.child_nests)
                        child.request |= struct.request
                        child.reply |= struct.reply
                if attr_set in struct.child_nests:
                    struct.recursive = True

        self._sort_pure_types()

    def _load_attr_use(self):
        for _, struct in self.pure_nested_structs.items():
            if struct.request:
                for _, arg in struct.member_list():
                    arg.request = True
            if struct.reply:
                for _, arg in struct.member_list():
                    arg.reply = True

        for root_set, rs_members in self.root_sets.items():
            for attr, spec in self.attr_sets[root_set].items():
                if attr in rs_members["request"]:
                    spec.request = True
                if attr in rs_members["reply"]:
                    spec.reply = True

    def _load_global_policy(self):
        global_set = set()
        attr_set_name = None
        for op_name, op in self.ops.items():
            if not op:
                continue
            if "attribute-set" not in op:
                continue

            if attr_set_name is None:
                attr_set_name = op["attribute-set"]
            if attr_set_name != op["attribute-set"]:
                raise Exception("For a global policy all ops must use the same set")

            for op_mode in ["do", "dump"]:
                if op_mode in op:
                    req = op[op_mode].get("request")
                    if req:
                        global_set.update(req.get("attributes", []))

        self.global_policy = []
        self.global_policy_set = attr_set_name
        for attr in self.attr_sets[attr_set_name]:
            if attr in global_set:
                self.global_policy.append(attr)

    def _load_hooks(self):
        for op in self.ops.values():
            for op_mode in ["do", "dump"]:
                if op_mode not in op:
                    continue
                for when in ["pre", "post"]:
                    if when not in op[op_mode]:
                        continue
                    name = op[op_mode][when]
                    if name in self.hooks[when][op_mode]["set"]:
                        continue
                    self.hooks[when][op_mode]["set"].add(name)
                    self.hooks[when][op_mode]["list"].append(name)


class RenderInfo:
    def __init__(self, cw, family, ku_space, op, op_mode, attr_set=None):
        self.family = family
        self.nl = cw.nlib
        self.ku_space = ku_space
        self.op_mode = op_mode
        self.op = op

        self.fixed_hdr = None
        if op and op.fixed_header:
            self.fixed_hdr = "struct " + c_lower(op.fixed_header)

        # 'do' and 'dump' response parsing is identical
        self.type_consistent = True
        if op_mode != "do" and "dump" in op:
            if "do" in op:
                if ("reply" in op["do"]) != ("reply" in op["dump"]):
                    self.type_consistent = False
                elif "reply" in op["do"] and op["do"]["reply"] != op["dump"]["reply"]:
                    self.type_consistent = False
            else:
                self.type_consistent = False

        self.attr_set = attr_set
        if not self.attr_set:
            self.attr_set = op["attribute-set"]

        self.type_name_conflict = False
        if op:
            self.type_name = c_lower(op.name)
        else:
            self.type_name = c_lower(attr_set)
            if attr_set in family.consts:
                self.type_name_conflict = True

        self.cw = cw

        self.struct = dict()
        if op_mode == "notify":
            op_mode = "do"
        for op_dir in ["request", "reply"]:
            if op:
                type_list = []
                if op_dir in op[op_mode]:
                    type_list = op[op_mode][op_dir]["attributes"]
                self.struct[op_dir] = Struct(family, self.attr_set, type_list=type_list)
        if op_mode == "event":
            self.struct["reply"] = Struct(
                family, self.attr_set, type_list=op["event"]["attributes"]
            )


class CodeWriter:
    def __init__(self, nlib, out_file=None, overwrite=True):
        self.nlib = nlib
        self._overwrite = overwrite

        self._nl = False
        self._block_end = False
        self._silent_block = False
        self._ind = 0
        self._ifdef_block = None
        if out_file is None:
            self._out = os.sys.stdout
        else:
            self._out = tempfile.NamedTemporaryFile("w+")
            self._out_file = out_file

    def __del__(self):
        self.close_out_file()

    def close_out_file(self):
        if self._out == os.sys.stdout:
            return
        # Avoid modifying the file if contents didn't change
        self._out.flush()
        if not self._overwrite and os.path.isfile(self._out_file):
            if filecmp.cmp(self._out.name, self._out_file, shallow=False):
                return
        with open(self._out_file, "w+") as out_file:
            self._out.seek(0)
            shutil.copyfileobj(self._out, out_file)
            self._out.close()
        self._out = os.sys.stdout

    @classmethod
    def _is_cond(cls, line):
        return (
            line.startswith("if") or line.startswith("while") or line.startswith("for")
        )

    def p(self, line, add_ind=0):
        if self._block_end:
            self._block_end = False
            if line.startswith("else"):
                line = "} " + line
            else:
                self._out.write("\t" * self._ind + "}\n")

        if self._nl:
            self._out.write("\n")
            self._nl = False

        ind = self._ind
        if line[-1] == ":":
            ind -= 1
        if self._silent_block:
            ind += 1
        self._silent_block = line.endswith(")") and CodeWriter._is_cond(line)
        if line[0] == "#":
            ind = 0
        if add_ind:
            ind += add_ind
        self._out.write("\t" * ind + line + "\n")

    def nl(self):
        self._nl = True

    def block_start(self, line=""):
        if line:
            line = line + " "
        self.p(line + "{")
        self._ind += 1

    def block_end(self, line=""):
        if line and line[0] not in {";", ","}:
            line = " " + line
        self._ind -= 1
        self._nl = False
        if not line:
            # Delay printing closing bracket in case "else" comes next
            if self._block_end:
                self._out.write("\t" * (self._ind + 1) + "}\n")
            self._block_end = True
        else:
            self.p("}" + line)

    def write_doc_line(self, doc, indent=True):
        words = doc.split()
        line = " *"
        for word in words:
            if len(line) + len(word) >= 79:
                self.p(line)
                line = " *"
                if indent:
                    line += "  "
            line += " " + word
        self.p(line)

    def write_func_prot(self, qual_ret, name, args=None, doc=None, suffix=""):
        if not args:
            args = ["void"]

        if doc:
            self.p("/*")
            self.p(" * " + doc)
            self.p(" */")

        oneline = qual_ret
        if qual_ret[-1] != "*":
            oneline += " "
        oneline += f"{name}({', '.join(args)}){suffix}"

        if len(oneline) < 80:
            self.p(oneline)
            return

        v = qual_ret
        if len(v) > 3:
            self.p(v)
            v = ""
        elif qual_ret[-1] != "*":
            v += " "
        v += name + "("
        ind = "\t" * (len(v) // 8) + " " * (len(v) % 8)
        delta_ind = len(v) - len(ind)
        v += args[0]
        i = 1
        while i < len(args):
            next_len = len(v) + len(args[i])
            if v[0] == "\t":
                next_len += delta_ind
            if next_len > 76:
                self.p(v + ",")
                v = ind
            else:
                v += ", "
            v += args[i]
            i += 1
        self.p(v + ")" + suffix)

    def write_func_lvar(self, local_vars):
        if not local_vars:
            return

        if type(local_vars) is str:
            local_vars = [local_vars]

        local_vars.sort(key=len, reverse=True)
        for var in local_vars:
            self.p(var)
        self.nl()

    def write_func(self, qual_ret, name, body, args=None, local_vars=None):
        self.write_func_prot(qual_ret=qual_ret, name=name, args=args)
        self.write_func_lvar(local_vars=local_vars)

        self.block_start()
        for line in body:
            self.p(line)
        self.block_end()

    def writes_defines(self, defines):
        longest = 0
        for define in defines:
            if len(define[0]) > longest:
                longest = len(define[0])
        longest = ((longest + 8) // 8) * 8
        for define in defines:
            line = "#define " + define[0]
            line += "\t" * ((longest - len(define[0]) + 7) // 8)
            if type(define[1]) is int:
                line += str(define[1])
            elif type(define[1]) is str:
                line += '"' + define[1] + '"'
            self.p(line)

    def write_struct_init(self, members):
        longest = max([len(x[0]) for x in members])
        longest += 1  # because we prepend a .
        longest = ((longest + 8) // 8) * 8
        for one in members:
            line = "." + one[0]
            line += "\t" * ((longest - len(one[0]) - 1 + 7) // 8)
            line += "= " + str(one[1]) + ","
            self.p(line)

    def ifdef_block(self, config):
        config_option = None
        if config:
            config_option = "CONFIG_" + c_upper(config)
        if self._ifdef_block == config_option:
            return

        if self._ifdef_block:
            self.p("#endif /* " + self._ifdef_block + " */")
        if config_option:
            self.p("#ifdef " + config_option)
        self._ifdef_block = config_option


scalars = {"u8", "u16", "u32", "u64", "s32", "s64", "uint", "sint"}

direction_to_suffix = {"reply": "_rsp", "request": "_req", "": ""}

op_mode_to_wrapper = {
    "do": "",
    "dump": "_list",
    "notify": "_ntf",
    "event": "",
}

_C_KW = {
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
}


def rdir(direction):
    if direction == "reply":
        return "request"
    if direction == "request":
        return "reply"
    return direction


def op_prefix(ri, direction, deref=False):
    suffix = f"_{ri.type_name}"

    if not ri.op_mode or ri.op_mode == "do":
        suffix += f"{direction_to_suffix[direction]}"
    else:
        if direction == "request":
            suffix += "_req_dump"
        else:
            if ri.type_consistent:
                if deref:
                    suffix += f"{direction_to_suffix[direction]}"
                else:
                    suffix += op_mode_to_wrapper[ri.op_mode]
            else:
                suffix += "_rsp"
                suffix += "_dump" if deref else "_list"

    return f"{ri.family.c_name}{suffix}"


def type_name(ri, direction, deref=False):
    return f"{op_prefix(ri, direction, deref=deref)}"


def print_prototype(ri, direction, terminate=True, doc=None):
    suffix = ";" if terminate else ""

    fname = ri.op.render_name
    if ri.op_mode == "dump":
        fname += "_dump"

    args = ["ynl_cpp::ynl_socket&  ys"]
    if "request" in ri.op[ri.op_mode]:
        args.append(
            f"{type_name(ri, direction)}& " + f"{direction_to_suffix[direction][1:]}"
        )

    ret = "int"
    if "reply" in ri.op[ri.op_mode]:
        ret = f"std::unique_ptr<{type_name(ri, rdir(direction))}>"

    ri.cw.write_func_prot(ret, fname, args, doc=doc, suffix=suffix)


def print_req_prototype(ri):
    print_prototype(ri, "request", doc=ri.op["doc"])


def print_dump_prototype(ri):
    print_prototype(ri, "request")


def put_typol_fwd(cw, struct):
    cw.p(f"extern struct ynl_policy_nest {struct.render_name}_nest;")


def put_typol(cw, struct):
    type_max = struct.attr_set.max_name
    cw.block_start(
        line=f"static std::array<ynl_policy_attr,{type_max} + 1> {struct.render_name}_policy = []()"
    )

    cw.p(f"std::array<ynl_policy_attr,{type_max} + 1> arr{{}};")

    for _, arg in struct.member_list():
        arg.attr_typol(cw)

    cw.p("return arr;")
    cw.block_end(line="();")
    cw.nl()

    cw.block_start(line=f"struct ynl_policy_nest {struct.render_name}_nest =")
    cw.p(f".max_attr = {type_max},")
    cw.p(f".table = {struct.render_name}_policy.data(),")
    cw.block_end(line=";")
    cw.nl()


def _put_enum_to_str_helper(cw, render_name, map_name, arg_name, enum=None):
    args = [f"int {arg_name}"]
    if enum:
        args = [enum.user_type + " " + arg_name]
    cw.write_func_prot("std::string_view", f"{render_name}_str", args)
    cw.block_start()
    if enum and enum.type == "flags":
        cw.p(f"{arg_name} = ({enum.user_type})(ffs({arg_name}) - 1);")
    cw.p(f"if ({arg_name} < 0 || {arg_name} >= (int)({map_name}.size()))")
    cw.p('return "";')
    cw.p(f"return {map_name}[{arg_name}];")
    cw.block_end()
    cw.nl()


def put_op_name_fwd(family, cw):
    cw.write_func_prot(
        "std::string_view", f"{family.c_name}_op_str", ["int op"], suffix=";"
    )


def put_op_name(family, cw):
    map_name = f"{family.c_name}_op_strmap"
    max_num = "0"
    for op_name, op in family.msgs.items():
        if op.rsp_value:
            # Make sure we don't add duplicated entries, if multiple commands
            # produce the same response in legacy families.
            if family.rsp_by_value[op.rsp_value] != op:
                continue

            if op.req_value == op.rsp_value:
                max_num = f"{op.enum_name}"
            else:
                max_num = f"{op.rsp_value}"

    cw.block_start(
        line=f"static constexpr std::array<std::string_view, {max_num} + 1> {map_name} = []()"
    )
    cw.p(f"std::array<std::string_view, {max_num} + 1> arr{{}};")
    for op_name, op in family.msgs.items():
        if op.rsp_value:
            # Make sure we don't add duplicated entries, if multiple commands
            # produce the same response in legacy families.
            if family.rsp_by_value[op.rsp_value] != op:
                continue

            if op.req_value == op.rsp_value:
                cw.p(f'arr[{op.enum_name}] = "{op_name}";')
            else:
                cw.p(f'arr[{op.rsp_value}] = "{op_name}";')
    cw.p("return arr;")
    cw.block_end(line="();")
    cw.nl()

    _put_enum_to_str_helper(cw, family.c_name + "_op", map_name, "op")


def put_enum_to_str_fwd(family, cw, enum):
    args = [enum.user_type + " value"]
    cw.write_func_prot("std::string_view", f"{enum.render_name}_str", args, suffix=";")


def put_enum_to_str(family, cw, enum):
    map_name = f"{enum.render_name}_strmap"
    max_num = "0"
    for entry in enum.entries.values():
        max_num = f"{entry.value}"
    cw.block_start(
        line=f"static constexpr std::array<std::string_view, {max_num} + 1> {map_name} = []()"
    )
    cw.p(f"std::array<std::string_view, {max_num} + 1> arr{{}};")
    for entry in enum.entries.values():
        cw.p(f'arr[{entry.value}] = "{entry.name}";')
    cw.p("return arr;")
    cw.block_end(line="();")
    cw.nl()

    _put_enum_to_str_helper(cw, enum.render_name, map_name, "value", enum=enum)


def put_req_nested_prototype(ri, struct, suffix=";"):
    func_args = [
        "struct nlmsghdr *nlh",
        "unsigned int attr_type",
        f"const {struct.ref_name} obj",
    ]

    ri.cw.write_func_prot("int", f"{struct.render_name}_put", func_args, suffix=suffix)


def put_req_nested(ri, struct):
    put_req_nested_prototype(ri, struct, suffix="")
    ri.cw.block_start()
    ri.cw.write_func_lvar("struct nlattr *nest;")

    ri.cw.p("nest = ynl_attr_nest_start(nlh, attr_type);")

    for _, arg in struct.member_list():
        arg.attr_put(ri, "obj")

    ri.cw.p("ynl_attr_nest_end(nlh, nest);")

    ri.cw.nl()
    ri.cw.p("return 0;")
    ri.cw.block_end()
    ri.cw.nl()


def _multi_parse(ri, struct, init_lines, local_vars):
    if struct.nested:
        iter_line = "ynl_attr_for_each_nested(attr, nested)"
    else:
        if ri.fixed_hdr:
            local_vars += ["void *hdr;"]
        iter_line = "ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len)"

    array_nests = set()
    multi_attrs = set()
    needs_parg = False
    for arg, aspec in struct.member_list():
        if aspec["type"] == "indexed-array" and "sub-type" in aspec:
            if aspec["sub-type"] == "nest":
                local_vars.append(f"const struct nlattr *attr_{aspec.c_name};")
                array_nests.add(arg)
            else:
                raise Exception(f'Not supported sub-type {aspec["sub-type"]}')
        if "multi-attr" in aspec:
            multi_attrs.add(arg)
        needs_parg |= "nested-attributes" in aspec
    if array_nests or multi_attrs:
        local_vars.append("int i;")
    if needs_parg:
        local_vars.append("struct ynl_parse_arg parg;")
        init_lines.append("parg.ys = yarg->ys;")

    all_multi = array_nests | multi_attrs

    for anest in sorted(all_multi):
        local_vars.append(f"unsigned int n_{struct[anest].c_name} = 0;")

    ri.cw.block_start()
    ri.cw.write_func_lvar(local_vars)

    for line in init_lines:
        ri.cw.p(line)
    ri.cw.nl()

    for arg in struct.inherited:
        ri.cw.p(f"dst->{arg} = {arg};")

    if ri.fixed_hdr:
        ri.cw.p("hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));")
        ri.cw.p(f"memcpy(&dst->_hdr, hdr, sizeof({ri.fixed_hdr}));")
    for anest in sorted(all_multi):
        aspec = struct[anest]
        ri.cw.p(f"if (dst->{aspec.c_name}.size() > 0)")
        ri.cw.p(
            f'return ynl_error_parse(yarg, "attribute already present ({struct.attr_set.name}.{aspec.name})");'
        )

    ri.cw.nl()
    ri.cw.block_start(line=iter_line)
    ri.cw.p("unsigned int type = ynl_attr_type(attr);")
    ri.cw.nl()

    first = True
    for _, arg in struct.member_list():
        good = arg.attr_get(ri, "dst", first=first)
        # First may be 'unused' or 'pad', ignore those
        first &= not good

    ri.cw.block_end()
    ri.cw.nl()

    for anest in sorted(array_nests):
        aspec = struct[anest]

        ri.cw.block_start(line=f"if (n_{aspec.c_name})")
        ri.cw.p(f"dst->{aspec.c_name}.resize(n_{aspec.c_name});")
        # ri.cw.p(f"dst->n_{aspec.c_name} = n_{aspec.c_name};")
        ri.cw.p("i = 0;")
        ri.cw.p(f"parg.rsp_policy = &{aspec.nested_render_name}_nest;")
        ri.cw.block_start(line=f"ynl_attr_for_each_nested(attr, attr_{aspec.c_name})")
        ri.cw.p(f"parg.data = &dst->{aspec.c_name}[i];")
        ri.cw.p(
            f"if ({aspec.nested_render_name}_parse(&parg, attr, ynl_attr_type(attr)))"
        )
        ri.cw.p("return YNL_PARSE_CB_ERROR;")
        ri.cw.p("i++;")
        ri.cw.block_end()
        ri.cw.block_end()
    ri.cw.nl()

    for anest in sorted(multi_attrs):
        aspec = struct[anest]
        ri.cw.block_start(line=f"if (n_{aspec.c_name})")
        ri.cw.p(f"dst->{aspec.c_name}.resize(n_{aspec.c_name});")
        # ri.cw.p(f"dst->n_{aspec.c_name} = n_{aspec.c_name};")
        ri.cw.p("i = 0;")
        if "nested-attributes" in aspec:
            ri.cw.p(f"parg.rsp_policy = &{aspec.nested_render_name}_nest;")
        ri.cw.block_start(line=iter_line)
        ri.cw.block_start(line=f"if (ynl_attr_type(attr) == {aspec.enum_name})")
        if "nested-attributes" in aspec:
            ri.cw.p(f"parg.data = &dst->{aspec.c_name}[i];")
            ri.cw.p(f"if ({aspec.nested_render_name}_parse(&parg, attr))")
            ri.cw.p("return YNL_PARSE_CB_ERROR;")
        elif aspec.type in scalars:
            ri.cw.p(f"dst->{aspec.c_name}[i] = ynl_attr_get_{aspec.type}(attr);")
        else:
            raise Exception("Nest parsing type not supported yet")
        ri.cw.p("i++;")
        ri.cw.block_end()
        ri.cw.block_end()
        ri.cw.block_end()
    ri.cw.nl()

    if struct.nested:
        ri.cw.p("return 0;")
    else:
        ri.cw.p("return YNL_PARSE_CB_OK;")
    ri.cw.block_end()
    ri.cw.nl()


def parse_rsp_nested_prototype(ri, struct, suffix=";"):
    func_args = ["struct ynl_parse_arg *yarg", "const struct nlattr *nested"]
    for arg in struct.inherited:
        func_args.append("__u32 " + arg)

    ri.cw.write_func_prot(
        "int", f"{struct.render_name}_parse", func_args, suffix=suffix
    )


def parse_rsp_nested(ri, struct):
    parse_rsp_nested_prototype(ri, struct, suffix="")

    local_vars = [
        "const struct nlattr *attr;",
        f"{struct.ptr_name}dst = ({struct.ptr_name})yarg->data;",
    ]
    init_lines = []

    _multi_parse(ri, struct, init_lines, local_vars)


def parse_rsp_msg(ri, deref=False):
    if "reply" not in ri.op[ri.op_mode] and ri.op_mode != "event":
        return

    func_args = ["const struct nlmsghdr *nlh", "struct ynl_parse_arg *yarg"]

    local_vars = [
        f'{type_name(ri, "reply", deref=deref)} *dst;',
        "const struct nlattr *attr;",
    ]
    init_lines = [f'dst = ({type_name(ri, "reply", deref=deref)}*)yarg->data;']

    ri.cw.write_func_prot(
        "int", f'{op_prefix(ri, "reply", deref=deref)}_parse', func_args
    )

    if ri.struct["reply"].member_list():
        _multi_parse(ri, ri.struct["reply"], init_lines, local_vars)
    else:
        # Empty reply
        ri.cw.block_start()
        ri.cw.p("return YNL_PARSE_CB_OK;")
        ri.cw.block_end()
        ri.cw.nl()


def print_req(ri):
    ret_ok = "0"
    ret_err = "-1"
    direction = "request"
    local_vars = [
        "struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };",
        "struct nlmsghdr *nlh;",
        "int err;",
    ]

    if "reply" in ri.op[ri.op_mode]:
        ret_ok = "rsp"
        ret_err = "NULL"
        local_vars += [f"std::unique_ptr<{type_name(ri, rdir(direction))}> rsp;"]

    if ri.fixed_hdr:
        local_vars += ["size_t hdr_len;", "void *hdr;"]

    print_prototype(ri, direction, terminate=False)
    ri.cw.block_start()
    ri.cw.write_func_lvar(local_vars)

    ri.cw.p(
        f"nlh = ynl_gemsg_start_req(ys, {ri.nl.get_family_id()}, {ri.op.enum_name}, 1);"
    )

    ri.cw.p(
        f"((struct ynl_sock*)ys)->req_policy = &{ri.struct['request'].render_name}_nest;"
    )
    if "reply" in ri.op[ri.op_mode]:
        ri.cw.p(f"yrs.yarg.rsp_policy = &{ri.struct['reply'].render_name}_nest;")
    ri.cw.nl()

    if ri.fixed_hdr:
        ri.cw.p("hdr_len = sizeof(req->_hdr);")
        ri.cw.p("hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);")
        ri.cw.p("memcpy(hdr, &req->_hdr, hdr_len);")
        ri.cw.nl()

    for _, attr in ri.struct["request"].member_list():
        attr.attr_put(ri, "req")
    ri.cw.nl()

    if "reply" in ri.op[ri.op_mode]:
        ri.cw.p(f"rsp.reset(new {type_name(ri, rdir(direction))}());")
        ri.cw.p("yrs.yarg.data = rsp.get();")
        ri.cw.p(f"yrs.cb = {op_prefix(ri, 'reply')}_parse;")
        if ri.op.value is not None:
            ri.cw.p(f"yrs.rsp_cmd = {ri.op.enum_name};")
        else:
            ri.cw.p(f"yrs.rsp_cmd = {ri.op.rsp_value};")
        ri.cw.nl()
    ri.cw.p("err = ynl_exec(ys, nlh, &yrs);")
    ri.cw.p("if (err < 0)")
    if "reply" in ri.op[ri.op_mode]:
        ri.cw.p("return nullptr;")
    else:
        ri.cw.p("return -1;")
    ri.cw.nl()

    ri.cw.p(f"return {ret_ok};")
    ri.cw.nl()

    ri.cw.block_end()


def print_dump(ri):
    direction = "request"
    print_prototype(ri, direction, terminate=False)
    ri.cw.block_start()
    local_vars = [
        "struct ynl_dump_no_alloc_state yds = {};",
        "struct nlmsghdr *nlh;",
        "int err;",
    ]

    if ri.fixed_hdr:
        local_vars += ["size_t hdr_len;", "void *hdr;"]

    ri.cw.write_func_lvar(local_vars)

    ri.cw.p(f"auto ret = std::make_unique<{type_name(ri, rdir(direction))}>();")

    ri.cw.p("yds.yarg.ys = ys;")
    ri.cw.p(f"yds.yarg.rsp_policy = &{ri.struct['reply'].render_name}_nest;")
    ri.cw.p("yds.yarg.data = ret.get();")
    ri.cw.p(
        f"yds.alloc_cb = [](void* arg)->void*{{return &(static_cast<{type_name(ri, rdir(direction))}*>(arg)->objs.emplace_back());}};"
    )

    ri.cw.p(f"yds.cb = {op_prefix(ri, 'reply', deref=True)}_parse;")
    if ri.op.value is not None:
        ri.cw.p(f"yds.rsp_cmd = {ri.op.enum_name};")
    else:
        ri.cw.p(f"yds.rsp_cmd = {ri.op.rsp_value};")
    ri.cw.nl()
    ri.cw.p(
        f"nlh = ynl_gemsg_start_dump(ys, {ri.nl.get_family_id()}, {ri.op.enum_name}, 1);"
    )

    if ri.fixed_hdr:
        ri.cw.p("hdr_len = sizeof(req->_hdr);")
        ri.cw.p("hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);")
        ri.cw.p("memcpy(hdr, &req->_hdr, hdr_len);")
        ri.cw.nl()

    if "request" in ri.op[ri.op_mode]:
        ri.cw.p(
            f"((struct ynl_sock*)ys)->req_policy = &{ri.struct['request'].render_name}_nest;"
        )
        ri.cw.nl()
        for _, attr in ri.struct["request"].member_list():
            attr.attr_put(ri, "req")
    ri.cw.nl()

    ri.cw.p("err = ynl_exec_dump_no_alloc(ys, nlh, &yds);")
    ri.cw.p("if (err < 0)")
    ri.cw.p("return nullptr;")
    ri.cw.nl()

    ri.cw.p("return ret;")
    ri.cw.nl()
    ri.cw.block_end()


def _print_type(ri, direction, struct):
    suffix = f"_{ri.type_name}{direction_to_suffix[direction]}"
    if not direction and ri.type_name_conflict:
        suffix += "_t"

    if ri.op_mode == "dump":
        suffix += "_dump"

    ri.cw.block_start(line=f"struct {ri.family.c_name}{suffix}")

    if ri.fixed_hdr:
        ri.cw.p(ri.fixed_hdr + " _hdr;")
        ri.cw.nl()

    for arg in struct.inherited:
        ri.cw.p(f"std::optional<__u32> {arg};")

    for _, attr in struct.member_list():
        attr.struct_member(ri)

    ri.cw.block_end(line=";")
    ri.cw.nl()


def print_type(ri, direction):
    _print_type(ri, direction, ri.struct[direction])


def print_type_full(ri, struct):
    _print_type(ri, "", struct)


def print_parse_prototype(ri, direction, terminate=True):
    suffix = "_rsp" if direction == "reply" else "_req"
    term = ";" if terminate else ""

    ri.cw.write_func_prot(
        "void",
        f"{ri.op.render_name}{suffix}_parse",
        ["const struct nlattr **tb", f"struct {ri.op.render_name}{suffix} *req"],
        suffix=term,
    )


def print_req_type(ri):
    if len(ri.struct["request"].attr_list) == 0:
        return
    print_type(ri, "request")


def print_rsp_type(ri):
    if (ri.op_mode == "do" or ri.op_mode == "dump") and "reply" in ri.op[ri.op_mode]:
        direction = "reply"
    elif ri.op_mode == "event":
        direction = "reply"
    else:
        return
    print_type(ri, direction)


def print_wrapped_type(ri):
    ri.cw.block_start(line=f"struct {type_name(ri, 'reply')}")
    if ri.op_mode == "dump":
        ri.cw.p(f"std::list<{type_name(ri, 'reply', deref=True)}> objs;")
    ri.cw.block_end(line=";")
    ri.cw.nl()


def print_req_policy_fwd(cw, struct, ri=None, terminate=True):
    if terminate and ri and policy_should_be_static(struct.family):
        return

    if terminate:
        prefix = "extern "
    else:
        if ri and policy_should_be_static(struct.family):
            prefix = "static "
        else:
            prefix = ""

    suffix = ";" if terminate else " = {"

    max_attr = struct.attr_max_val
    if ri:
        name = ri.op.render_name
        if ri.op.dual_policy:
            name += "_" + ri.op_mode
    else:
        name = struct.render_name
    cw.p(
        f"{prefix}const struct nla_policy {name}_nl_policy[{max_attr.enum_name} + 1]{suffix}"
    )


def print_req_policy(cw, struct, ri=None):
    if ri and ri.op:
        cw.ifdef_block(ri.op.get("config-cond", None))
    print_req_policy_fwd(cw, struct, ri=ri, terminate=False)
    for _, arg in struct.member_list():
        arg.attr_policy(cw)
    cw.p("};")
    cw.ifdef_block(None)
    cw.nl()


def kernel_can_gen_family_struct(family):
    return family.proto == "genetlink"


def policy_should_be_static(family):
    return family.kernel_policy == "split" or kernel_can_gen_family_struct(family)


def _render_user_ntf_entry(ri, op):
    ri.cw.block_start(line=f"arr[{op.enum_name}] = ")
    # ri.cw.p(f".alloc_sz\t= sizeof({type_name(ri, 'event')}),")
    ri.cw.p(f".cb\t\t= {op_prefix(ri, 'reply', deref=True)}_parse,")
    ri.cw.p(f".policy\t\t= &{ri.struct['reply'].render_name}_nest,")
    # ri.cw.p(f".free\t\t= (void *){op_prefix(ri, 'notify')}_free,")
    ri.cw.block_end(line=";")


def render_user_family(family, cw, prototype):
    symbol = f"const struct ynl_family ynl_{family.c_name}_family"
    proto = f"const struct ynl_family& get_ynl_{family.c_name}_family()"
    if prototype:
        cw.p(f"{proto};")
        return

    if family.ntfs:
        max_num = "0"
        for ntf_op_name, ntf_op in family.ntfs.items():
            max_num = ntf_op.enum_name
        cw.block_start(
            line=f"static constexpr std::array<ynl_ntf_info, {max_num} + 1> {family['name']}_ntf_info = []()"
        )
        cw.p(f"std::array<ynl_ntf_info, {max_num} + 1> arr{{}};")
        for ntf_op_name, ntf_op in family.ntfs.items():
            if "notify" in ntf_op:
                op = family.ops[ntf_op["notify"]]
                ri = RenderInfo(cw, family, "user", op, "notify")
            elif "event" in ntf_op:
                ri = RenderInfo(cw, family, "user", ntf_op, "event")
            else:
                raise Exception("Invalid notification " + ntf_op_name)
            _render_user_ntf_entry(ri, ntf_op)
        for op_name, op in family.ops.items():
            if "event" not in op:
                continue
            ri = RenderInfo(cw, family, "user", op, "event")
            _render_user_ntf_entry(ri, op)
        cw.p("return arr;")
        cw.block_end(line="();")
        cw.nl()

    cw.block_start(f"{symbol} = ")
    cw.p(f'.name\t\t= "{family.c_name}",')
    if family.fixed_header:
        cw.p(
            f".hdr_len\t= sizeof(struct genlmsghdr) + sizeof(struct {c_lower(family.fixed_header)}),"
        )
    else:
        cw.p(".hdr_len\t= sizeof(struct genlmsghdr),")
    if family.ntfs:
        cw.p(f".ntf_info\t= {family['name']}_ntf_info.data(),")
        cw.p(f".ntf_info_size\t= {family['name']}_ntf_info.size(),")
    cw.block_end(line=";")

    cw.block_start(f"{proto}")
    cw.p(f"return ynl_{family.c_name}_family;")
    cw.block_end(line=";")


def family_contains_bitfield32(family):
    for _, attr_set in family.attr_sets.items():
        if attr_set.subset_of:
            continue
        for _, attr in attr_set.items():
            if attr.type == "bitfield32":
                return True
    return False


def find_kernel_root(full_path):
    sub_path = ""
    while True:
        sub_path = os.path.join(os.path.basename(full_path), sub_path)
        full_path = os.path.dirname(full_path)
        maintainers = os.path.join(full_path, "MAINTAINERS")
        if os.path.exists(maintainers):
            return full_path, sub_path[:-1]


def main():
    parser = argparse.ArgumentParser(description="Netlink simple parsing generator")
    parser.add_argument("--mode", dest="mode", type=str, required=True)
    parser.add_argument("--spec", dest="spec", type=str, required=True)
    parser.add_argument("--header", dest="header", action="store_true", default=None)
    parser.add_argument("--source", dest="header", action="store_false")
    parser.add_argument("--user-header", nargs="+", default=[])
    parser.add_argument(
        "--cmp-out",
        action="store_true",
        default=None,
        help="Do not overwrite the output file if the new output is identical to the old",
    )
    parser.add_argument("--exclude-op", action="append", default=[])
    parser.add_argument("-o", dest="out_file", type=str, default=None)
    args = parser.parse_args()

    if args.header is None:
        parser.error("--header or --source is required")

    exclude_ops = [re.compile(expr) for expr in args.exclude_op]

    try:
        parsed = Family(args.spec, exclude_ops)
        if parsed.license != "((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)":
            print("Spec license:", parsed.license)
            print(
                "License must be: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)"
            )
            os.sys.exit(1)
    except yaml.YAMLError as exc:
        print(exc)
        os.sys.exit(1)
        return

    supported_models = ["unified"]
    if args.mode in ["user"]:
        supported_models += ["directional"]
    if parsed.msg_id_model not in supported_models:
        print(
            f"Message enum-model {parsed.msg_id_model} not supported for {args.mode} generation"
        )
        os.sys.exit(1)

    cw = CodeWriter(BaseNlLib(), args.out_file, overwrite=(not args.cmp_out))

    # _, spec_kernel = find_kernel_root(args.spec)
    spec_kernel = ""
    if args.header:
        cw.p(f"/* SPDX-License-Identifier: {parsed.license} */")
    else:
        cw.p(f"// SPDX-License-Identifier: {parsed.license}")
    cw.p("/* Do not edit directly, auto-generated from: */")
    cw.p(f"/*\t{spec_kernel} */")
    cw.p(f"/* YNL-GEN {args.mode} {'header' if args.header else 'source'} */")
    if args.exclude_op or args.user_header:
        line = ""
        line += " --user-header ".join([""] + args.user_header)
        line += " --exclude-op ".join([""] + args.exclude_op)
        cw.p(f"/* YNL-ARG{line} */")
    cw.nl()

    hdr_prot = f"_LINUX_{parsed.c_name.upper()}_GEN_H"
    if args.header:
        cw.p("#ifndef " + hdr_prot)
        cw.p("#define " + hdr_prot)
        cw.nl()

    if args.header:
        cw.p("#include <linux/types.h>")
        if family_contains_bitfield32(parsed):
            cw.p("#include <linux/netlink.h>")
        cw.p("#include <stdlib.h>")
        cw.p("#include <string.h>")
        cw.nl()
        cw.p("#include <list>")
        cw.p("#include <memory>")
        cw.p("#include <optional>")
        cw.p("#include <string>")
        cw.p("#include <string_view>")
        cw.p("#include <vector>")
        cw.nl()
        cw.p('#include "ynl.hpp"')
    else:
        hdr_file = os.path.basename(args.out_file[:-4]) + ".hpp"
        cw.p(f'#include "{hdr_file}"')
        cw.nl()
        cw.p("#include <array>")
    cw.nl()
    headers = [parsed.uapi_header]
    for definition in parsed["definitions"]:
        if "header" in definition:
            headers.append(definition["header"])
    for one in headers:
        cw.p(f"#include <{one}>")
    cw.nl()

    if not args.header:
        cw.p("#include <linux/genetlink.h>")
        cw.nl()
        for one in args.user_header:
            cw.p(f'#include "{one}"')

    cw.p("namespace ynl_cpp {")
    if args.header:
        render_user_family(parsed, cw, True)
    cw.nl()

    if args.header:
        cw.p("/* Enums */")
        put_op_name_fwd(parsed, cw)

        for name, const in parsed.consts.items():
            if isinstance(const, EnumSet):
                put_enum_to_str_fwd(parsed, cw, const)
        cw.nl()

        cw.p("/* Common nested types */")
        for attr_set, struct in parsed.pure_nested_structs.items():
            ri = RenderInfo(cw, parsed, args.mode, "", "", attr_set)
            print_type_full(ri, struct)

        for op_name, op in parsed.ops.items():
            cw.p(f"/* ============== {op.enum_name} ============== */")

            if "do" in op and "event" not in op:
                cw.p(f"/* {op.enum_name} - do */")
                ri = RenderInfo(cw, parsed, args.mode, op, "do")
                print_req_type(ri)
                cw.nl()
                print_rsp_type(ri)
                cw.nl()
                print_req_prototype(ri)
                cw.nl()

            if "dump" in op:
                cw.p(f"/* {op.enum_name} - dump */")
                ri = RenderInfo(cw, parsed, args.mode, op, "dump")
                print_req_type(ri)
                if not ri.type_consistent:
                    print_rsp_type(ri)
                print_wrapped_type(ri)
                print_dump_prototype(ri)
                cw.nl()

            if op.has_ntf:
                cw.p(f"/* {op.enum_name} - notify */")
                ri = RenderInfo(cw, parsed, args.mode, op, "notify")
                if not ri.type_consistent:
                    raise Exception(
                        f"Only notifications with consistent types supported ({op.name})"
                    )
                print_wrapped_type(ri)

        for op_name, op in parsed.ntfs.items():
            if "event" in op:
                ri = RenderInfo(cw, parsed, args.mode, op, "event")
                cw.p(f"/* {op.enum_name} - event */")
                print_rsp_type(ri)
                cw.nl()
                print_wrapped_type(ri)
        cw.nl()
    else:
        cw.p("/* Enums */")
        put_op_name(parsed, cw)

        for name, const in parsed.consts.items():
            if isinstance(const, EnumSet):
                put_enum_to_str(parsed, cw, const)
        cw.nl()

        has_recursive_nests = False
        cw.p("/* Policies */")
        for struct in parsed.pure_nested_structs.values():
            if struct.recursive:
                put_typol_fwd(cw, struct)
                has_recursive_nests = True
        if has_recursive_nests:
            cw.nl()
        for name in parsed.pure_nested_structs:
            struct = Struct(parsed, name)
            put_typol(cw, struct)
        for name in parsed.root_sets:
            struct = Struct(parsed, name)
            put_typol(cw, struct)

        cw.p("/* Common nested types */")
        if has_recursive_nests:
            for attr_set, struct in parsed.pure_nested_structs.items():
                ri = RenderInfo(cw, parsed, args.mode, "", "", attr_set)
                # free_rsp_nested_prototype(ri)
                if struct.request:
                    put_req_nested_prototype(ri, struct)
                if struct.reply:
                    parse_rsp_nested_prototype(ri, struct)
            cw.nl()
        for attr_set, struct in parsed.pure_nested_structs.items():
            ri = RenderInfo(cw, parsed, args.mode, "", "", attr_set)

            # free_rsp_nested(ri, struct)
            if struct.request:
                put_req_nested(ri, struct)
            if struct.reply:
                parse_rsp_nested(ri, struct)

        for op_name, op in parsed.ops.items():
            cw.p(f"/* ============== {op.enum_name} ============== */")
            if "do" in op and "event" not in op:
                cw.p(f"/* {op.enum_name} - do */")
                ri = RenderInfo(cw, parsed, args.mode, op, "do")
                parse_rsp_msg(ri)
                print_req(ri)
                cw.nl()

            if "dump" in op:
                cw.p(f"/* {op.enum_name} - dump */")
                ri = RenderInfo(cw, parsed, args.mode, op, "dump")
                if not ri.type_consistent:
                    parse_rsp_msg(ri, deref=True)
                print_dump(ri)
                cw.nl()

            if op.has_ntf:
                cw.p(f"/* {op.enum_name} - notify */")
                ri = RenderInfo(cw, parsed, args.mode, op, "notify")
                if not ri.type_consistent:
                    raise Exception(
                        f"Only notifications with consistent types supported ({op.name})"
                    )

        for op_name, op in parsed.ntfs.items():
            if "event" in op:
                cw.p(f"/* {op.enum_name} - event */")

                ri = RenderInfo(cw, parsed, args.mode, op, "do")
                parse_rsp_msg(ri)

                ri = RenderInfo(cw, parsed, args.mode, op, "event")
        cw.nl()
        render_user_family(parsed, cw, False)

    cw.p("} //namespace ynl_cpp")

    if args.header:
        cw.p(f"#endif /* {hdr_prot} */")


if __name__ == "__main__":
    main()
