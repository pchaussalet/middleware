#+
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

from freenas.dispatcher.rpc import description
from task import Task, TaskDescription


@description("Evaluates given code fragment using background CLI instance")
class EvalCodeTask(Task):
    @classmethod
    def early_describe(cls):
        return "Evaluating code fragment"

    def describe(self, code):
        return TaskDescription("Evaluating code fragment")

    def verify(self, code):
        return []

    def run(self, code):
        return self.dispatcher.call_sync('clid.eval.eval_code', code)


@description("Evaluates given AST using background CLI instance")
class EvalASTTask(Task):
    @classmethod
    def early_describe(cls):
        return "Evaluating AST"

    def describe(self, code):
        return TaskDescription("Evaluating AST")

    def verify(self, ast):
        return []

    def run(self, ast):
        return self.dispatcher.call_sync('clid.eval.eval_ast', ast)


def _init(dispatcher, plugin):
    plugin.register_task_handler('cli.eval.ast', EvalASTTask)
    plugin.register_task_handler('cli.eval.code', EvalCodeTask)
