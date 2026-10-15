# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng

"""
Shared SDitH parameter module for sign testbenches.

Parses rtl/sdith_params_pkg.sv at import time and exposes every parameter as a
module-level name.  No values are hardcoded here; changing the SV file and
re-importing picks up the new values automatically.

Extra names added beyond what the SV file declares:
  LAMBDA_BYTES   - LAMBDA // 8
  TOTAL_LEAVES   - TAU * N_CAP
  LBYTES         - (R_ACC_SIZE + 7) // 8
  SW_REF_DIR     - path to matching sw_reference_implementation subdirectory
  SEED_SALT_FILE - SW_REF_DIR / seed_salt.txt
  read_seed_salt - helper to read seed/salt from a seed_salt.txt file
"""

import os
import re
import math

_tb_dir = os.path.dirname(os.path.abspath(__file__))
_sv_path = os.path.normpath(os.path.join(_tb_dir, '../../sdith_params_pkg.sv'))


# ---------------------------------------------------------------------------
# Helpers used during expression evaluation
# ---------------------------------------------------------------------------

def _clog2(x):
    if x <= 1:
        return 0
    return math.ceil(math.log2(x))


def _strip_comments(src):
    """Remove // line comments and /* */ block comments."""
    src = re.sub(r'/\*.*?\*/', ' ', src, flags=re.DOTALL)
    src = re.sub(r'//[^\n]*', '', src)
    return src


def _sv_ternary_to_python(expr):
    """Convert SV ternary COND ? A : B  ->  (A) if (COND) else (B), recursively.

    Processes sub-expressions inside parentheses first so that ternaries nested
    inside an outer paren group (e.g. ``8 * (COND ? A : B)``) are also handled.
    """
    # Step 1: recursively convert the contents of every (...) sub-expression.
    result = []
    i = 0
    while i < len(expr):
        if expr[i] == '(':
            depth = 1
            j = i + 1
            while j < len(expr) and depth > 0:
                if expr[j] == '(':
                    depth += 1
                elif expr[j] == ')':
                    depth -= 1
                j += 1
            inner = expr[i + 1:j - 1]
            result.append('(' + _sv_ternary_to_python(inner) + ')')
            i = j
        else:
            result.append(expr[i])
            i += 1
    expr = ''.join(result)

    # Step 2: convert a top-level ternary (depth-0 ?  ...  :  ...).
    depth = 0
    q_pos = None
    for i, c in enumerate(expr):
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif c == '?' and depth == 0:
            q_pos = i
            break
    if q_pos is None:
        return expr
    cond = expr[:q_pos].strip()
    rest = expr[q_pos + 1:]
    depth = 0
    c_pos = None
    for i, c in enumerate(rest):
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif c == ':' and depth == 0:
            c_pos = i
            break
    if c_pos is None:
        return expr
    true_val  = rest[:c_pos].strip()
    false_val = rest[c_pos + 1:].strip()
    # false_val may itself be a ternary chain (right-associative)
    false_val = _sv_ternary_to_python(false_val)
    return f'({true_val}) if ({cond}) else ({false_val})'


def _sv_to_python(expr):
    """Translate a SV expression string to evaluable Python."""
    # Remove (int) casts
    expr = re.sub(r'\(int\)\s*', '', expr)
    # Remove SV type casts: type'(expr) -> (expr)
    expr = re.sub(r"\w+'\(", '(', expr)
    # Remove _ separators inside numeric literals  (e.g. 36_000 -> 36000)
    expr = re.sub(r'(?<=\d)_(?=\d)', '', expr)
    # Convert bit literals: [n]'b<digits>  -> decimal integer
    expr = re.sub(r"\d*'b([01]+)", lambda m: str(int(m.group(1), 2)), expr)
    # Logical operators
    expr = expr.replace('&&', ' and ').replace('||', ' or ')
    # Single & used as logical-and between booleans in this SV file
    expr = re.sub(r'(?<![&])&(?![&])', ' and ', expr)
    # $clog2 -> Python helper
    expr = re.sub(r'\$clog2\s*\(', '_clog2(', expr)
    # Integer division: SV integer params use truncating /; use // in Python
    expr = re.sub(r'(?<!/)/(?!/)', '//', expr)
    # Ternary ? :  ->  Python conditional expression
    expr = _sv_ternary_to_python(expr)
    return expr


def _preprocess_defines(src):
    """Resolve `define / `ifdef / `ifndef / `else / `endif and substitute macros.

    Handles the patterns used in sdith_params_pkg.sv:
        `ifndef MACRO          `ifdef MACRO
        `define MACRO value        `MACRO;
        `endif                 `else
                                   default_expr;
                               `endif
    Then replaces all `MACRO references with their defined value.
    """
    defines = {}
    out_lines = []
    # Stack of (include_this_branch, any_branch_taken).
    # A line is emitted only when ALL stack entries have include=True.
    cond_stack = []

    def _active():
        return all(inc for inc, _ in cond_stack)

    for line in src.splitlines():
        stripped = line.strip()

        if stripped.startswith('`ifdef'):
            macro = stripped.split()[1] if len(stripped.split()) > 1 else ''
            taking = macro in defines
            cond_stack.append((taking, taking))
            continue

        if stripped.startswith('`ifndef'):
            macro = stripped.split()[1] if len(stripped.split()) > 1 else ''
            taking = macro not in defines
            cond_stack.append((taking, taking))
            continue

        if stripped.startswith('`else'):
            if cond_stack:
                _, any_taken = cond_stack[-1]
                taking = not any_taken
                cond_stack[-1] = (taking, any_taken or taking)
            continue

        if stripped.startswith('`endif'):
            if cond_stack:
                cond_stack.pop()
            continue

        if not _active():
            continue

        if stripped.startswith('`define'):
            parts = stripped.split(None, 2)
            if len(parts) >= 3:
                defines[parts[1]] = parts[2]
            continue

        out_lines.append(line)

    # Substitute `MACRO references with their values
    result = '\n'.join(out_lines)
    for macro, value in defines.items():
        result = result.replace(f'`{macro}', value)
    return result


def _parse_sv_params(sv_path):
    """Parse sdith_params_pkg.sv; return dict of evaluated parameter values."""
    if not os.path.isfile(sv_path):
        raise FileNotFoundError(f"sdith_params_pkg.sv not found at: {sv_path}")
    with open(sv_path) as f:
        src = f.read()
    src = _preprocess_defines(src)
    src = _strip_comments(src)

    namespace = {'_clog2': _clog2}

    # --- Extract enum values -------------------------------------------------
    enum_re = re.compile(
        r'typedef\s+enum\s+\w+(?:\s*\[\s*[^\]]+\s*\])?\s*\{([^}]+)\}',
        re.DOTALL,
    )
    for m in enum_re.finditer(src):
        counter = 0
        for item in m.group(1).split(','):
            item = item.strip()
            if not item:
                continue
            if '=' in item:
                name, val_str = item.split('=', 1)
                name    = name.strip()
                val_str = val_str.strip()
                # Convert bit literals in enum initialiser
                val_str = re.sub(
                    r"\d*'b([01]+)", lambda x: str(int(x.group(1), 2)), val_str
                )
                val = eval(val_str, namespace)
                namespace[name] = val
                counter = val + 1
            else:
                namespace[item] = counter
                counter += 1

    # --- Collect all parameter declarations ----------------------------------
    # Handles multi-line expressions; terminates at the closing semicolon.
    param_re = re.compile(
        r'\bparameter\s+(?:(?:int|integer|params_e|hash_e|enc_e)\s+)?(\w+)\s*=\s*(.*?);',
        re.DOTALL,
    )
    declarations = []
    for m in param_re.finditer(src):
        name     = m.group(1)
        expr_raw = re.sub(r'\s+', ' ', m.group(2).strip())
        declarations.append((name, expr_raw))

    # --- Evaluate with multiple passes to handle forward references ----------
    params    = {}
    remaining = list(declarations)
    for _ in range(len(declarations) + 1):
        if not remaining:
            break
        next_remaining = []
        for name, expr_raw in remaining:
            py_expr = _sv_to_python(expr_raw)
            try:
                val = eval(py_expr, {**namespace, **params})
                params[name]    = val
                namespace[name] = val
            except NameError:
                next_remaining.append((name, expr_raw))
            except Exception as e:
                raise RuntimeError(
                    f"Failed to evaluate parameter {name!r} = {expr_raw!r}\n"
                    f"  as Python: {py_expr!r}\n  error: {e}"
                )
        if len(next_remaining) == len(remaining):
            unresolved = [n for n, _ in next_remaining]
            raise RuntimeError(
                f"Cannot resolve parameters (circular or missing deps): {unresolved}"
            )
        remaining = next_remaining

    return params


def _apply_env_overrides(params):
    """Override SECURITY_LEVEL / PARAMETER_SET / CACHE_DEPTH from env vars if set.

    The Makefile exports SEC_LEVEL, PARAM_SET, and CACHE_DEPTH when given on
    the command line.  When present, override the values parsed from the SV
    file and re-evaluate all dependent parameters so everything stays consistent.
    """
    sec = os.environ.get('SEC_LEVEL')
    par = os.environ.get('PARAM_SET')
    hp  = os.environ.get('HALF_POLY')
    cd  = os.environ.get('CACHE_DEPTH')
    if sec is None and par is None and hp is None and cd is None:
        return params

    if sec is not None:
        params['SECURITY_LEVEL'] = int(sec)
    if par is not None:
        params['PARAMETER_SET'] = int(par)
    if hp is not None:
        params['HALF_POLY'] = int(hp)
    if cd is not None:
        params['CACHE_TREE_DEPTH'] = int(cd)

    # Re-read the SV source to get the raw expressions, then re-evaluate
    # everything with the overridden root values.
    with open(_sv_path) as f:
        src = _preprocess_defines(f.read())
    src = _strip_comments(src)

    namespace = {'_clog2': _clog2}

    # Re-extract enums
    enum_re = re.compile(
        r'typedef\s+enum\s+\w+(?:\s*\[\s*[^\]]+\s*\])?\s*\{([^}]+)\}',
        re.DOTALL,
    )
    for m in enum_re.finditer(src):
        counter = 0
        for item in m.group(1).split(','):
            item = item.strip()
            if not item:
                continue
            if '=' in item:
                name, val_str = item.split('=', 1)
                name = name.strip()
                val_str = re.sub(
                    r"\d*'b([01]+)", lambda x: str(int(x.group(1), 2)), val_str.strip()
                )
                val = eval(val_str, namespace)
                namespace[name] = val
                counter = val + 1
            else:
                namespace[item] = counter
                counter += 1

    # Re-collect parameter declarations
    param_re = re.compile(
        r'\bparameter\s+(?:(?:int|integer|params_e|hash_e|enc_e)\s+)?(\w+)\s*=\s*(.*?);',
        re.DOTALL,
    )
    declarations = []
    for m in param_re.finditer(src):
        name = m.group(1)
        expr_raw = re.sub(r'\s+', ' ', m.group(2).strip())
        declarations.append((name, expr_raw))

    # Seed with ONLY the overridden root values - all others must be
    # re-evaluated from their expressions to pick up the new roots.
    new_params = {
        'SECURITY_LEVEL': params['SECURITY_LEVEL'],
        'PARAMETER_SET':  params['PARAMETER_SET'],
        'HALF_POLY':      params.get('HALF_POLY', 0),
    }
    if 'CACHE_TREE_DEPTH' in params and cd is not None:
        new_params['CACHE_TREE_DEPTH'] = params['CACHE_TREE_DEPTH']
    namespace.update(new_params)

    # Multi-pass re-evaluation
    frozen = {'SECURITY_LEVEL', 'PARAMETER_SET', 'HALF_POLY'}
    if cd is not None:
        frozen.add('CACHE_TREE_DEPTH')
    remaining = [(n, e) for n, e in declarations
                 if n not in frozen]
    for _ in range(len(declarations) + 1):
        if not remaining:
            break
        next_remaining = []
        for name, expr_raw in remaining:
            py_expr = _sv_to_python(expr_raw)
            try:
                val = eval(py_expr, {**namespace, **new_params})
                new_params[name] = val
                namespace[name] = val
            except NameError:
                next_remaining.append((name, expr_raw))
        if len(next_remaining) == len(remaining):
            break
        remaining = next_remaining

    return new_params


# ---------------------------------------------------------------------------
# Parse and expose all SV parameters as module-level names
# ---------------------------------------------------------------------------
_sv_params = _apply_env_overrides(_parse_sv_params(_sv_path))
globals().update(_sv_params)

# ---------------------------------------------------------------------------
# Derived values not present in the SV package
# ---------------------------------------------------------------------------
LAMBDA_BYTES = _sv_params['LAMBDA'] // 8
TOTAL_LEAVES = _sv_params['TAU'] * _sv_params['N_CAP']
LBYTES       = (_sv_params['R_ACC_SIZE'] + 7) // 8

# Map (SECURITY_LEVEL, PARAMETER_SET) to the vectors subdirectory name
_SEC_NAME = {1: 's1', 3: 's3', 5: 's5'}
_PAR_NAME = {0: 'short', 1: 'fast'}
_cfg_sec = _sv_params.get('SECURITY_LEVEL', 1)
_cfg_par = _sv_params.get('PARAMETER_SET', 1)
_vec_subdir = f"{_SEC_NAME.get(_cfg_sec, 's1')}_{_PAR_NAME.get(_cfg_par, 'fast')}"

SW_REF_DIR = os.path.normpath(os.path.join(
    _tb_dir,
    '../../../sw_reference_implementation/sdith_cat1_fast/vectors',
    _vec_subdir,
))
SEED_SALT_FILE = os.path.join(SW_REF_DIR, 'seed_salt.txt')


def read_seed_salt(path=None):
    """Return (seed, salt) integers read from a seed_salt.txt file."""
    if path is None:
        path = SEED_SALT_FILE
    seed = salt = None
    with open(path) as f:
        for line in f:
            if line.startswith('seed:'):
                seed = int(line.split(':', 1)[1].strip(), 16)
            elif line.startswith('salt:'):
                salt = int(line.split(':', 1)[1].strip(), 16)
    assert seed is not None and salt is not None, \
        f"seed_salt.txt missing seed or salt: {path}"
    return seed, salt
