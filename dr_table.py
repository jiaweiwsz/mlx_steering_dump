# Copyright (c) 2020 Mellanox Technologies, Inc.  All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from dr_utilities import _srd, print_dr, dr_obj, inc_indent, dec_indent, dr_dump_rec_type


class dr_dump_table(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "id", "domain_id", "type", "level"]
        self.data = dict(zip(keys, data))
        self.matcher_list = []
        self.table_rx = None
        self.table_tx = None

    def dump_str(self):
        return "table %s: level: %s, type: %s\n" % (
               _srd(self.data, "id"),
               _srd(self.data, "level"),
               _srd(self.data, "type"))

    def print_tree_view(self, dump_ctx, verbose, raw):
        print_dr(self.dump_str())
        inc_indent()

        for m in self.matcher_list:
            dump_ctx.matcher = m
            dump_ctx.rule = None
            m.print_tree_view(dump_ctx, verbose, raw)

        dec_indent()

    def print_rule_view(self, dump_ctx, verbose, raw):
        for m in self.matcher_list:
            dump_ctx.matcher = m
            dump_ctx.rule = None
            m.print_rule_view(dump_ctx, verbose, raw)

    def add_matcher(self, matcher):
        self.matcher_list.append(matcher)

    def add_table_rx_tx(self, table_rx_tx):
        if table_rx_tx.data['dr_dump_rec_type'] == dr_dump_rec_type.DR_DUMP_REC_TYPE_TABLE_RX.value[0]:
            self.table_rx = table_rx_tx
        else:
            self.table_tx = table_rx_tx


class dr_dump_table_rx_tx(dr_obj):
    def __init__(self, data):
        keys = ["dr_dump_rec_type", "table_id", "s_anchor"]
        self.data = dict(zip(keys, data))

    def dump_string(self):
        return "icm_addr_rx: %s\n" % (_srd(self.data, "s_anchor"))