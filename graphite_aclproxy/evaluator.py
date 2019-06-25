"""
evaluator.py taken from graphite-web.


Copyright 2008 Orbitz WorldWide

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from .grammar import grammar
import six


def evaluateScalarTokens(tokens):
    if tokens.number:
        if tokens.number.integer:
            return int(tokens.number.integer)
        if tokens.number.float:
            return float(tokens.number.float)
        if tokens.number.scientific:
            return float(tokens.number.scientific[0])

        raise ValueError("unknown numeric type in target evaluator")

    if tokens.string:
        return tokens.string[1:-1]

    if tokens.boolean:
        return tokens.boolean[0] == 'true'

    if tokens.none:
        return None

    raise ValueError("unknown token in target evaluator")


def extractPathExpressions(requestContext, targets):
    # Returns a list of unique pathExpressions found in the targets list

    pathExpressions = set()

    def extractPathExpression(requestContext, tokens, replacements=None):
        if tokens.template:
            arglist = dict()
            if tokens.template.kwargs:
                arglist.update(dict([(kwarg.argname, evaluateScalarTokens(kwarg.args[0])) for kwarg in tokens.template.kwargs]))
            if tokens.template.args:
                arglist.update(dict([(str(i+1), evaluateScalarTokens(arg)) for i, arg in enumerate(tokens.template.args)]))
            if 'template' in requestContext:
                arglist.update(requestContext['template'])
            extractPathExpression(requestContext, tokens.template, arglist)
        elif tokens.expression:
            extractPathExpression(requestContext, tokens.expression, replacements)
            if tokens.expression.pipedCalls:
                for token in tokens.expression.pipedCalls:
                    extractPathExpression(requestContext, token, replacements)
        elif tokens.pathExpression:
            expression = tokens.pathExpression
            if replacements:
                for name in replacements:
                    if expression != '$'+name:
                        expression = expression.replace('$'+name, str(replacements[name]))
            pathExpressions.add(expression)
        elif tokens.call:
            # if we're prefetching seriesByTag, pass the entire call back as a path expression
            if tokens.call.funcname == 'seriesByTag':
                pathExpressions.add(tokens.call.raw)
            else:
                for a in tokens.call.args:
                    extractPathExpression(requestContext, a, replacements)

    for target in targets:
        if not target:
            continue

        if isinstance(target, six.string_types):
            if not target.strip():
                continue
            target = grammar.parseString(target)
        extractPathExpression(requestContext, target)

    return list(pathExpressions)

