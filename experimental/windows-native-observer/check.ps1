<#
Static gate for the W6/W7 observer. It

  1. parses observer.ps1 and check.ps1,
  2. checks the syntax tree for assignments to automatic/read-only variables,
     for forbidden commands, for the exact harness file-name list, and for the
     ordering rules (the path gate and the native-mode refusal must both come
     before Add-Type),
  3. evaluates the real pure helper functions taken from the observer's syntax
     tree, including the bounded stream reader,
  4. validates its own paths and %TEMP%, and only then
  5. compiles WinObserver.cs with Add-Type without calling any native method.

It creates no file of its own, starts no observer mode, takes no lock and
never runs the observer body. Add-Type does start the .NET compiler as a child
process, which writes compiler temporaries into %TEMP%; that is why step 4
runs before step 5. A static gate means no observation and no native method
call, not no compiler process.

  powershell -NoProfile -NonInteractive -File check.ps1

Exit 0 when every check passed, 1 on any failure.
#>
$ErrorActionPreference = 'Stop'
$failed = $false
$observerAst = $null
$trees = @{}

function Report([string]$text) { Write-Output $text }
function Fail([string]$text) { $script:failed = $true; Write-Output $text }

# UserPath is public in Windows PowerShell 5.1. UnqualifiedPath is an
# implementation detail and is not exposed through the normal PS adapter.
function Get-DeclaredVariableName($VariablePath) {
    $name = [string]$VariablePath.UserPath
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'AST variable has no public UserPath' }
    if ($name -match '^(global|local|script|private):(.+)$') { return $Matches[2] }
    return $name
}

foreach ($case in @(@('home', 'home'), @('script:home', 'home'), @('global:PID', 'PID'),
        @('local:Host', 'Host'), @('private:args', 'args'), @('env:TEMP', 'env:TEMP'))) {
    $vp = New-Object System.Management.Automation.VariablePath($case[0])
    if ((Get-DeclaredVariableName $vp) -cne $case[1]) { Fail 'AST variable scope handling failed' }
}

# Automatic and read-only PowerShell variables. Repurposing one of these is
# refused: $HOME in particular is read-only and variable names are
# case-insensitive, so `$home = ...` fails at runtime.
$Automatic = @('home', 'host', 'pid', 'error', 'args', 'input', 'matches', 'this', 'psitem', '_', 'profile',
    'pshome', 'psscriptroot', 'pscommandpath', 'psboundparameters', 'myinvocation', 'executioncontext',
    'true', 'false', 'null', 'lastexitcode', 'stacktrace', 'psculture', 'pscmdlet', 'switch', 'foreach')
$Forbidden = @('Stop-Process', 'Remove-Item', 'Set-Acl', 'Set-MpPreference', 'Set-ExecutionPolicy',
    'Invoke-Expression', 'Invoke-WebRequest', 'Start-Process', 'New-Service', 'Set-Content', 'Out-File',
    'Clear-Content', 'Move-Item', 'Rename-Item')
# A cmdlet denylist alone proves nothing: the same effects are reachable through
# .NET members, which are not CommandAst nodes. These member names are refused
# wherever they are invoked. The members this harness DOES use on purpose
# (Process::Start for `--version`, Directory::CreateDirectory for the
# disposable home, StreamWriter.Write for the results file, SetOwner and
# AddAccessRule on a NEW DirectorySecurity) are deliberately absent from the
# list and are described in the README's safety boundary instead.
$ForbiddenMembers = @('Kill', 'Delete', 'SetAccessControl', 'SetAttributes', 'Move', 'MoveTo', 'Replace',
    'Encrypt', 'Decrypt', 'WriteAllText', 'WriteAllBytes', 'WriteAllLines', 'AppendAllText', 'AppendAllLines',
    'SetCreationTime', 'SetLastWriteTime', 'TerminateProcess', 'CloseMainWindow', 'SetEnvironmentVariable')
$ExpectedHarness = @('observer.ps1', 'WinObserver.cs', 'check.ps1', 'expectations.mjs', 'lib.mjs', 'evaluate.mjs')

foreach ($script in 'observer.ps1', 'check.ps1') {
    $tokens = $null
    $errors = $null
    $parsed = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $script), [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $failed = $true
        foreach ($e in $errors) { Report ("parse error {0}:{1}: {2}" -f $script, $e.Extent.StartLineNumber, $e.Message) }
    } else {
        Report "parse ok: $script"
        $trees[$script] = $parsed
        if ($script -eq 'observer.ps1') { $observerAst = $parsed }
    }
}

# ---- Syntax-tree checks (no execution) ----------------------------------
# Only variables that are assignment targets count. Walking every descendant
# would falsely reject `$object[$HOME] = ...` or `$object.Member++`.
function Get-WriteTargetVariables($target) {
    if ($target -is [System.Management.Automation.Language.AttributedExpressionAst]) {
        Get-WriteTargetVariables $target.Child
    } elseif ($target -is [System.Management.Automation.Language.ArrayLiteralAst]) {
        foreach ($element in $target.Elements) { Get-WriteTargetVariables $element }
    } elseif ($target -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $target
    }
}

function Get-AutomaticWriteProblems($tree) {
    foreach ($assignment in $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        foreach ($variable in @(Get-WriteTargetVariables $assignment.Left)) {
            $declaredName = Get-DeclaredVariableName $variable.VariablePath
            if ($Automatic -contains $declaredName) { "assignment:$declaredName" }
        }
    }
    foreach ($unary in $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.UnaryExpressionAst] }, $true)) {
        if ($unary.TokenKind.ToString() -notmatch 'PlusPlus|MinusMinus') { continue }
        foreach ($variable in @(Get-WriteTargetVariables $unary.Child)) {
            $declaredName = Get-DeclaredVariableName $variable.VariablePath
            if ($Automatic -contains $declaredName) { "mutation:$declaredName" }
        }
    }
}

# The called helper must itself terminate. Its complete AST is constrained to
# the three current statements: emit the diagnostic, record the literal setup
# code, then exit with that same literal code. No conditional, early return,
# additional block or second/scoped definition may hide a nonterminating path.
function Test-TerminationDefinition($tree, [string]$functionName, [int]$exitCode, [string]$prefix, [int]$beforeOffset) {
    $definitions = @($tree.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            (($node.Name -replace '^(global|local|script|private):', '') -ieq $functionName)
        }, $true))
    if ($definitions.Count -ne 1) { return $false }
    $definition = $definitions[0]
    if ($definition.Name -cne $functionName -or $definition.IsFilter -or $definition.IsWorkflow) { return $false }
    if (-not [object]::ReferenceEquals($definition.Parent, $tree.EndBlock) -or
        $definition.Extent.EndOffset -ge $beforeOffset) { return $false }
    if ($definition.Parameters.Count -ne 1 -or $definition.Parameters[0].Extent.Text -cne '[string]$why') { return $false }
    $scriptBody = $definition.Body
    if ($null -ne $scriptBody.ParamBlock -or $null -ne $scriptBody.DynamicParamBlock -or
        $null -ne $scriptBody.BeginBlock -or $null -ne $scriptBody.ProcessBlock -or $null -eq $scriptBody.EndBlock) { return $false }
    if (@($scriptBody.FindAll({ param($node) $node -is [System.Management.Automation.Language.TrapStatementAst] }, $true)).Count -ne 0) { return $false }
    $statements = @($scriptBody.EndBlock.Statements)
    if ($statements.Count -ne 3) { return $false }
    $diagnostic = $statements[0]
    $expectedDiagnostic = 'Write-Output "' + $prefix + ': $why"'
    if ($diagnostic -isnot [System.Management.Automation.Language.PipelineAst] -or
        $diagnostic.PipelineElements.Count -ne 1 -or
        $diagnostic.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandAst] -or
        ($diagnostic.Extent.Text -replace '\s+', ' ').Trim() -cne $expectedDiagnostic) { return $false }
    $setCode = $statements[1]
    if ($setCode -isnot [System.Management.Automation.Language.AssignmentStatementAst] -or
        $setCode.Operator.ToString() -ne 'Equals' -or $setCode.Left.Extent.Text -cne '$script:SetupExit' -or
        $setCode.Right.Extent.Text.Trim() -cne [string]$exitCode) { return $false }
    $exitStatement = $statements[2]
    if ($exitStatement -isnot [System.Management.Automation.Language.ExitStatementAst] -or
        $null -eq $exitStatement.Pipeline -or $exitStatement.Pipeline.Extent.Text.Trim() -cne [string]$exitCode) { return $false }
    $true
}

# This is deliberately an exact contract, not a general control-flow proof.
# The one true assignment must be top-level, and the exact refusal statement
# must immediately precede the sole Add-Type command in the same top-level
# try body. No additional reference (including a parameter or mutation) to the
# switch is accepted. These checks inspect ASTs; they never run the observer.
function Test-NativeRefusalAst($tree) {
    $switchUses = @($tree.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
            ($node.VariablePath.UserPath -match '(^|:)NATIVE_MODES_REFUSED$')
        }, $true))
    if ($switchUses.Count -ne 2) { return $false }
    $assignments = @($tree.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ieq '$NATIVE_MODES_REFUSED'
        }, $true))
    if ($assignments.Count -ne 1) { return $false }
    $assignment = $assignments[0]
    if ($assignment.Right.Extent.Text.Trim() -ine '$true' -or $assignment.Operator.ToString() -ne 'Equals') { return $false }
    if (-not [object]::ReferenceEquals($assignment.Parent, $tree.EndBlock)) { return $false }
    $compiles = @($tree.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type'
        }, $true))
    if ($compiles.Count -ne 1) { return $false }
    $compilePipeline = $compiles[0].Parent
    if ($compilePipeline -isnot [System.Management.Automation.Language.PipelineAst] -or $compilePipeline.PipelineElements.Count -ne 1) { return $false }
    $block = $compilePipeline.Parent
    if ($block -isnot [System.Management.Automation.Language.StatementBlockAst]) { return $false }
    $setupTry = $block.Parent
    if ($setupTry -isnot [System.Management.Automation.Language.TryStatementAst] -or
        -not [object]::ReferenceEquals($setupTry.Body, $block) -or
        -not [object]::ReferenceEquals($setupTry.Parent, $tree.EndBlock)) { return $false }
    if ($assignment.Extent.EndOffset -ge $setupTry.Extent.StartOffset) { return $false }
    if (-not (Test-TerminationDefinition $tree 'Refuse' 3 'refused' $setupTry.Extent.StartOffset) -or
        -not (Test-TerminationDefinition $tree 'Stop-Unknown' 2 'unknown' $setupTry.Extent.StartOffset)) { return $false }
    $statements = @($block.Statements)
    $index = -1
    for ($i = 0; $i -lt $statements.Count; $i++) {
        if ([object]::ReferenceEquals($statements[$i], $compilePipeline)) { $index = $i; break }
    }
    if ($index -lt 1) { return $false }
    $refusal = $statements[$index - 1]
    if ($refusal -isnot [System.Management.Automation.Language.IfStatementAst] -or
        $refusal.Clauses.Count -ne 1 -or $null -ne $refusal.ElseClause) { return $false }
    $condition = $refusal.Clauses[0].Item1.Extent.Text -replace '\s+', ''
    if ($condition -cne '$NATIVE_MODES_REFUSED-and($Mode-eq''preflight''-or$Mode-eq''observe'')') { return $false }
    $body = $refusal.Clauses[0].Item2.Statements
    if ($body.Count -ne 1 -or ($body[0].Extent.Text -replace '\s+', ' ').Trim() -cne 'Refuse $NativeRefusalReason') { return $false }
    $true
}

function Parse-Only([string]$text) {
    $parseTokens = $null
    $parseErrors = $null
    $parsedTree = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$parseTokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'AST mutation fixture did not parse' }
    $parsedTree
}

# Literal source-text substitution for AST-only fixtures. Do not use a member
# named Replace: the same name is forbidden for filesystem replacement APIs.
function Replace-SourceText([string]$text, [string]$needle, [string]$replacement) {
    if ([string]::IsNullOrEmpty($needle)) { throw 'empty source-text mutation anchor' }
    [string]::Join($replacement, $text.Split([string[]]@($needle), [StringSplitOptions]::None))
}

foreach ($name in $trees.Keys) {
    $tree = $trees[$name]
    foreach ($problem in @(Get-AutomaticWriteProblems $tree)) {
        Fail ("automatic variable write in {0}: {1}" -f $name, $problem)
    }
    $loops = $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)
    foreach ($loop in $loops) {
        $varName = Get-DeclaredVariableName $loop.Variable.VariablePath
        if ($Automatic -contains $varName.ToLowerInvariant()) {
            Fail ("automatic variable used as a loop variable in {0} line {1}: `${2}" -f $name, $loop.Extent.StartLineNumber, $varName)
        }
    }
    $params = $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.ParameterAst] }, $true)
    foreach ($p in $params) {
        $varName = Get-DeclaredVariableName $p.Name.VariablePath
        if ($Automatic -contains $varName.ToLowerInvariant()) {
            Fail ("automatic variable used as a parameter in {0} line {1}: `${2}" -f $name, $p.Extent.StartLineNumber, $varName)
        }
    }
    $commands = $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $commands) {
        $called = $c.GetCommandName()
        if ($called -and ($Forbidden -contains $called)) {
            Fail ("forbidden command in {0} line {1}: {2}" -f $name, $c.Extent.StartLineNumber, $called)
        }
    }
    # The same effects through .NET members, which are not commands.
    $members = $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
    foreach ($m in $members) {
        $called = $m.Member.Extent.Text
        if ($called -and ($ForbiddenMembers -contains $called)) {
            Fail ("forbidden member call in {0} line {1}: {2}" -f $name, $m.Extent.StartLineNumber, $called)
        }
    }
}
if (-not $failed) { Report 'syntax-tree checks ok (no automatic-variable assignment, no forbidden cmdlet or .NET member)' }

if ($null -ne $observerAst) {
    $commands = $observerAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    $offsetOf = {
        param($commandName)
        $found = @($commands | Where-Object { $_.GetCommandName() -eq $commandName } | Sort-Object { $_.Extent.StartOffset })
        if ($found.Count -eq 0) { -1 } else { $found[0].Extent.StartOffset }
    }
    $addTypeAt = & $offsetOf 'Add-Type'
    $gateAt = & $offsetOf 'Assert-PathGate'
    if ($gateAt -lt 0) { Fail 'observer.ps1 never calls Assert-PathGate' }
    elseif ($addTypeAt -lt 0) { Fail 'observer.ps1 never calls Add-Type' }
    elseif ($gateAt -gt $addTypeAt) { Fail 'observer.ps1 compiles before its path and TEMP gate' }
    else { Report 'ordering ok: observer.ps1 gates paths and TEMP before Add-Type' }
    if (-not (Test-NativeRefusalAst $observerAst)) { Fail 'observer.ps1 lost the exact top-level native refusal contract' }
    else { Report 'refusal ok: exact native refusal immediately precedes Add-Type in the same setup try' }
    try {
        $source = $observerAst.Extent.Text
        $line = 'if ($NATIVE_MODES_REFUSED -and ($Mode -eq ''preflight'' -or $Mode -eq ''observe'')) { Refuse $NativeRefusalReason }'
        if (-not $source.Contains($line)) { throw 'native refusal mutation anchor missing' }
        $compile = 'Add-Type -Path (Join-Path $PSScriptRoot ''WinObserver.cs'')'
        if (-not $source.Contains($compile)) { throw 'compile mutation anchor missing' }
        $variants = @{
            removed = Replace-SourceText $source $line ''
            moved = Replace-SourceText (Replace-SourceText $source $line '') $compile ($compile + "`n" + $line)
            conditional_false = Replace-SourceText $source $line ('if ($false) { ' + $line + ' }')
            condition_and_false = Replace-SourceText $source '$NATIVE_MODES_REFUSED -and ($Mode' '$NATIVE_MODES_REFUSED -and $false -and ($Mode'
            second_assignment = Replace-SourceText $source $line ('$NATIVE_MODES_REFUSED = $false' + "`n" + $line)
            parameter_override = ('param([bool]$NATIVE_MODES_REFUSED)' + "`n" + '$NATIVE_MODES_REFUSED = $true' + "`ntry { " + $line + "`n" + $compile + ' } catch {}')
            env_override = Replace-SourceText $source '$NATIVE_MODES_REFUSED = $true' '$NATIVE_MODES_REFUSED = $env:NATIVE_MODES_REFUSED'
        }
        foreach ($variant in $variants.Keys) {
            if (Test-NativeRefusalAst (Parse-Only $variants[$variant])) { throw "native refusal mutation accepted: $variant" }
        }
        # Mutate only source text and parse it. None of these altered helper
        # definitions, including their exit statements, is ever executed.
        foreach ($spec in @(@('Refuse', 'refused', 3), @('Stop-Unknown', 'unknown', 2))) {
            $functionName = $spec[0]
            $prefix = $spec[1]
            $exitCode = [string]$spec[2]
            $diagnostic = 'Write-Output "' + $prefix + ': $why"'
            $setCode = '$script:SetupExit = ' + $exitCode
            $exitText = 'exit ' + $exitCode
            $header = 'function ' + $functionName + '([string]$why) { '
            $definitionText = $header + $diagnostic + '; ' + $setCode + '; ' + $exitText + ' }'
            if (-not $source.Contains($definitionText)) { throw "termination definition mutation anchor missing: $functionName" }
            $definitionVariants = @{
                removed_definition = ''
                removed_exit = $header + $diagnostic + '; ' + $setCode + ' }'
                changed_exit = $header + $diagnostic + '; ' + $setCode + '; exit 0 }'
                changed_setup_code = $header + $diagnostic + '; $script:SetupExit = 0; ' + $exitText + ' }'
                conditional_exit = $header + $diagnostic + '; ' + $setCode + '; if ($false) { ' + $exitText + ' } }'
                early_return = $header + 'return; ' + $diagnostic + '; ' + $setCode + '; ' + $exitText + ' }'
                added_trap = $header + 'trap { continue }; ' + $diagnostic + '; ' + $setCode + '; ' + $exitText + ' }'
                return_instead_of_exit = $header + $diagnostic + '; ' + $setCode + '; return ' + $exitCode + ' }'
                duplicate_definition = $definitionText + "`n" + $definitionText
                conditional_definition = 'if ($false) { ' + $definitionText + ' }'
                nested_definition = 'function UncalledFixture { ' + $definitionText + ' }'
                scoped_duplicate = $definitionText + "`nfunction script:" + $functionName + '([string]$why) { return }'
            }
            foreach ($variant in $definitionVariants.Keys) {
                $mutated = Replace-SourceText $source $definitionText $definitionVariants[$variant]
                if (Test-NativeRefusalAst (Parse-Only $mutated)) { throw "termination mutation accepted: $functionName/$variant" }
            }
        }
        foreach ($text in '$HOME = 1', '$script:home = 1', '$local:PID, $ordinary = 1, 2', '++$global:host', '$private:HOME--') {
            if (@(Get-AutomaticWriteProblems (Parse-Only $text)).Count -eq 0) { throw "automatic variable mutation missed: $text" }
        }
        foreach ($text in '$ordinary = 1', '$ordinary++', '$object.home++', '$object[$HOME] = 1', '$env:HOME = ''example''') {
            if (@(Get-AutomaticWriteProblems (Parse-Only $text)).Count -ne 0) { throw "ordinary target falsely rejected: $text" }
        }
        Report 'AST-only mutation checks ok: refusal variants, terminating helper definitions and scoped/array/unary variable writes'
    } catch { Fail ('AST-only mutation check error: ' + $_.Exception.Message) }
    # The harness digest list must be exactly the evaluator's file-name set.
    $harness = $observerAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$HarnessNames'
        }, $true)
    if ($null -eq $harness) { Fail 'observer.ps1 has no $HarnessNames list' }
    else {
        $names = @($harness.Right.Find({ param($node) $node -is [System.Management.Automation.Language.ArrayLiteralAst] }, $true).Elements |
            ForEach-Object { $_.Value })
        if (@(Compare-Object ($names | Sort-Object) ($ExpectedHarness | Sort-Object)).Count -ne 0) {
            Fail ('observer.ps1 $HarnessNames differs from the expected file-name set: ' + ($names -join ','))
        } else { Report 'harness file-name set ok' }
    }
}

# ---- Pure helper functions, taken from the observer's syntax tree --------
# Each group of assertions runs in its own try/catch. A single `try` around
# everything would report only the first failure and silently skip the rest,
# which defeats the purpose of a gate that is supposed to say WHAT drifted.
function Invoke-CheckGroup([string]$Label, [scriptblock]$Body) {
    try {
        & $Body
        Report "pure helper checks ok: $Label"
    } catch {
        Fail ("pure helper check error ($Label): " + $_.Exception.Message)
    }
}

$helpersLoaded = $false
if ($null -ne $observerAst) {
    try {
        foreach ($name in 'Get-PathRelation', 'Test-LocalPathSpelling', 'Test-InsideDisposableDir', 'Test-PathGateSafe',
            'Test-CandidateTempSafe', 'Invoke-GuardedCreate', 'Invoke-GuardedSample', 'New-StreamChannel',
            'Read-BothStreams', 'Read-BoundedStream', 'Get-OpenerRole', 'Get-Dotted', 'Test-Denied', 'Test-Expect',
            'Test-SameDigests') {
            $fn = $observerAst.Find({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
                }, $true)
            if ($null -eq $fn) { throw "missing pure helper $name" }
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $helpersLoaded = $true
        Report 'pure helpers loaded from the observer syntax tree'
    } catch {
        Fail ('pure helper load error: ' + $_.Exception.Message)
    }
}

if ($helpersLoaded) {
    Invoke-CheckGroup 'path relations' {
        $cases = @(
            @('C:\Temp\A', 'c:\temp\a\', 'same'),
            @('C:\Temp\A\home', 'C:\Temp\A', 'inside'),
            @('C:\Users\op', 'C:\Users\op\.codex', 'contains'),
            @('C:\Users\op\.codex2', 'C:\Users\op\.codex', 'disjoint')
        )
        foreach ($c in $cases) {
            if ((Get-PathRelation $c[0] $c[1]) -ne $c[2]) { throw ('path relation regression: ' + ($c -join ' ')) }
        }
        # A drive root contains everything on its volume. This is why the
        # observer never gates a path's PARENT on this relation.
        if ((Get-PathRelation 'C:\' 'C:\Users\op\.codex') -ne 'contains') { throw 'a drive root must report contains' }
    }

    Invoke-CheckGroup 'path spelling' {
        # Only absolute local drive spellings are accepted; an ambiguous
        # spelling is refused, never rewritten.
        foreach ($good in 'C:\Temp', 'C:\', 'c:\Users\op\.codex', 'D:\a\b\c', 'C:\Temp\') {
            if (-not (Test-LocalPathSpelling $good)) { throw "accepted spelling rejected: $good" }
        }
        foreach ($bad in '\\?\C:\Temp', '\\.\C:\Temp', '\\server\share\x', '\rooted\x', 'C:relative', 'relative\x',
            'C:/Temp/x', 'C:\Temp\\x', 'C:\Temp\..\Users', 'C:\Temp\.', 'C:\Temp\x ', 'C:\Temp\x.', 'C:\Temp\ x',
            'C:\Temp\a:b', 'C:\Temp\a*b', 'C:\Temp\a?b', 'C:\Temp\a|b',
            'C:\Users\OP~1\.codex', 'C:\Temp\CODEX-~1\home', 'C:\Temp\ordinary~name', 'C:\Temp\~', '') {
            if (Test-LocalPathSpelling $bad) { throw "ambiguous spelling accepted: $bad" }
        }
    }

    Invoke-CheckGroup 'disposable directories' {
        # Matched per component, literally.
        if (-not (Test-InsideDisposableDir 'C:\Temp\codex-win-obs-0123456789ab\home')) { throw 'disposable directory not detected' }
        if (-not (Test-InsideDisposableDir 'D:\scratch\codex-win-obs-0123456789ab')) { throw 'disposable directory on another volume not detected' }
        if (Test-InsideDisposableDir 'C:\Temp\codex-win-obs-0123456789abc') { throw 'a longer suffix must not match' }
        if (-not (Test-InsideDisposableDir 'C:\Temp\codex-win-obs-0123456789AB')) { throw 'an uppercase hex suffix must be detected' }
        if (-not (Test-InsideDisposableDir 'C:\Temp\CODEX-WIN-OBS-0123456789AB\HOME')) { throw 'uppercase disposable components must be detected' }
        if (Test-InsideDisposableDir 'C:\Temp\codex-win-obs-[0-9a-f]') { throw 'the component match must be literal, not a wildcard' }
    }

    Invoke-CheckGroup 'path gate' {
        if ($null -ne (Test-PathGateSafe 'C:\Users\op\Documents\out.jsonl' 'C:\Users\op\.codex' $null $false)) { throw 'a safe output path must pass the gate' }
        if ((Test-PathGateSafe 'C:\Users\op\.codex\out.jsonl' 'C:\Users\op\.codex' $null $false) -ne 'user_home_overlap') { throw 'an output inside the real home must be refused' }
        if ((Test-PathGateSafe 'C:\Users\op\out.jsonl' 'C:\Users\op\.codex' 'C:\Users\op' $false) -ne 'env_home_overlap') { throw 'an output inside CODEX_HOME must be refused' }
        if ((Test-PathGateSafe 'C:\Temp\codex-win-obs-0123456789ab\o.jsonl' 'C:\Users\op\.codex' $null $false) -ne 'inside_disposable_dir') { throw 'an output inside a disposable directory must be refused' }
        if ($null -ne (Test-PathGateSafe 'C:\Temp\codex-win-obs-0123456789ab\home' 'C:\Users\op\.codex' $null $true)) { throw 'the disposable home itself must be allowed' }
        if ((Test-PathGateSafe '\\server\share\o.jsonl' 'C:\Users\op\.codex' $null $false) -ne 'path_spelling') { throw 'a UNC output must be refused' }
        if ((Test-PathGateSafe 'C:\Users\OP~1\out.jsonl' 'C:\Users\operator\.codex' $null $false) -ne 'path_spelling') { throw 'an 8.3-shaped path must be refused' }
        if ((Test-PathGateSafe 'C:\Temp\ordinary~name\out.jsonl' 'C:\Users\op\.codex' $null $false) -ne 'path_spelling') { throw 'a general tilde component must be conservatively refused' }
        if ((Test-PathGateSafe 'C:\Temp\CODEX-WIN-OBS-0123456789AB\out.jsonl' 'C:\Users\op\.codex' $null $false) -ne 'inside_disposable_dir') { throw 'an uppercase disposable output must be refused' }
    }

    Invoke-CheckGroup 'creation seam' {
        # TEMP inside a real home must refuse, and the creation callback must
        # never run.
        if (Test-CandidateTempSafe 'C:\Users\op\.codex\AppData\Temp' 'C:\Users\op\.codex' $null) { throw 'TEMP inside a real home must be refused' }
        if (Test-CandidateTempSafe 'C:\Users\op\AppData\Local\Temp' 'C:\Users\op\.codex' 'C:\Users\op\AppData\Local\Temp\x') { throw 'TEMP containing the env home must be refused' }
        if (-not (Test-CandidateTempSafe 'C:\Users\op\AppData\Local\Temp' 'C:\Users\op\.codex' $null)) { throw 'disjoint TEMP must be allowed' }
        $script:created = $false
        $refused = Invoke-GuardedCreate { Test-CandidateTempSafe 'C:\Users\op\.codex\AppData\Temp' 'C:\Users\op\.codex' $null } { $script:created = $true; [pscustomobject]@{ created = $true } }
        if ($script:created) { throw 'creation callback ran despite an unsafe TEMP' }
        if ($refused.created -ne $false) { throw 'guarded create must report not created on refusal' }
        $script:created = $false
        $allowed = Invoke-GuardedCreate { Test-CandidateTempSafe 'C:\Users\op\AppData\Local\Temp' 'C:\Users\op\.codex' $null } { $script:created = $true; [pscustomobject]@{ created = $true } }
        if (-not $script:created -or $allowed.created -ne $true) { throw 'guarded create must run the callback when the gate passes' }
    }

    Invoke-CheckGroup 'per-sample seam' {
        # The gate scriptblock is built from a LITERAL so the assertion cannot
        # accidentally compare the seam's own variable with itself: a gate that
        # dropped or rewrote the reason would otherwise still pass.
        foreach ($expected in 'process_exited', 'create_filetime_changed', 'process_query_failed', 'token_unreadable', 'user_sid_differs') {
            $script:ran = $false
            $gate = [scriptblock]::Create(("'" + $expected + "'"))
            $sample = Invoke-GuardedSample $gate { $script:ran = $true; 'probed' }
            if ($script:ran) { throw "sample operations ran despite the gate reason $expected" }
            if ($sample.ran -ne $false) { throw 'guarded sample must report that it did not run' }
            if ($sample.reason -cne $expected) { throw ('guarded sample reported reason ' + $sample.reason + ' instead of ' + $expected) }
        }
        $script:ran = $false
        $sample = Invoke-GuardedSample { $null } { $script:ran = $true; 'probed' }
        if (-not $script:ran -or $sample.ran -ne $true -or $sample.result -ne 'probed') { throw 'guarded sample must run when its gate passes' }
    }

    Invoke-CheckGroup 'opener roles' {
        # Recomputed, never read from a record.
        if ((Get-OpenerRole 7 '132' 7 '132' 5) -ne 'launched_codex') { throw 'the launched process must be labelled from PID and creation time' }
        if ((Get-OpenerRole 7 '999' 7 '132' 5) -ne 'other') { throw 'a reused PID must not be labelled as the launched process' }
        if ((Get-OpenerRole 7 '132' 7 '' 5) -ne 'other') { throw 'without a creation witness nothing is the launched process' }
        if ((Get-OpenerRole 5 '500' 7 '132' 5) -ne 'observer') { throw 'the observer must be labelled' }
        if ((Get-OpenerRole 9 '500' 7 '132' 5) -ne 'other') { throw 'an unrelated opener must be other' }
    }

    Invoke-CheckGroup 'bounded stream reads' {
        # End of stream, exactly at the cap, overflow, a failing stream, and a
        # stream that never ends. Only `complete` is usable evidence, and the
        # deadline is shared.
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $small = New-Object IO.MemoryStream (, [Text.Encoding]::UTF8.GetBytes('codex-cli 0.163.0'))
        $read = Read-BoundedStream $small 65536 $clock 5000
        if ($read.complete -ne $true -or $read.truncated -ne $false -or $read.timedOut -ne $false -or $read.error) { throw 'a short stream must read completely' }
        if ($read.text -cne 'codex-cli 0.163.0') { throw 'the decoded text must be exact' }

        $exact = New-Object IO.MemoryStream (, (New-Object byte[] 16))
        $read = Read-BoundedStream $exact 16 $clock 5000
        if ($read.complete -ne $true -or $read.truncated -ne $false) { throw 'exactly the cap is end of stream, not an overflow' }
        if ($read.bytes -ne 16) { throw 'exactly the cap must keep every byte' }

        $over = New-Object IO.MemoryStream (, (New-Object byte[] 100))
        $read = Read-BoundedStream $over 16 $clock 5000
        if ($read.truncated -ne $true -or $read.complete -eq $true) { throw 'more than the cap must be an overflow, never complete' }

        $closed = New-Object IO.MemoryStream
        $closed.Dispose()
        $read = Read-BoundedStream $closed 1024 $clock 5000
        if (-not $read.error -or $read.complete -eq $true) { throw 'a failing stream must record its error and never be complete' }

        # A pipe whose write end is still held (as an inherited descendant would
        # hold it) never reaches end of stream, so the deadline must bound it
        # without anything being terminated. Each case gets a FRESH pipe: a
        # stream serializes its async reads, so reusing one would make the
        # second case time out because it was queued, not because it blocked.
        # Disposing a pipe with a read still pending faults that orphaned task;
        # nothing observes it, which is benign under the default .NET policy.
        $blocked = New-Object IO.Pipes.AnonymousPipeServerStream ([IO.Pipes.PipeDirection]::In)
        try {
            $deadline = [Diagnostics.Stopwatch]::StartNew()
            $read = Read-BoundedStream $blocked 1024 $deadline 200
            if ($read.timedOut -ne $true -or $read.complete -eq $true) { throw 'an open pipe must time out, never complete' }
            if ($deadline.ElapsedMilliseconds -gt 4000) { throw 'the deadline did not bound the read' }
        } finally { $blocked.Dispose() }

        $blocked2 = New-Object IO.Pipes.AnonymousPipeServerStream ([IO.Pipes.PipeDirection]::In)
        try {
            # Concurrency: a blocked stream must not starve a finished one.
            $both = @(
                (New-StreamChannel (New-Object IO.MemoryStream (, [Text.Encoding]::UTF8.GetBytes('out'))) 1024),
                (New-StreamChannel $blocked2 1024)
            )
            $pair = [Diagnostics.Stopwatch]::StartNew()
            Read-BothStreams $both $pair 200 | Out-Null
            if ($both[0].complete -ne $true -or $both[0].text -cne 'out') { throw 'a finished stream must complete even beside a blocked one' }
            if ($both[1].timedOut -ne $true) { throw 'the blocked stream must be reported as timed out' }
        } finally { $blocked2.Dispose() }
    }

    Invoke-CheckGroup 'expectation and digest helpers' {
        $probe = [pscustomobject]@{ ok = $true; state = 'probed'; ranges = [pscustomobject]@{ rust = [pscustomobject]@{ win32 = 33 } } }
        if ((Test-Expect $probe @{ state = 'probed'; 'ranges.rust.win32' = 33 }) -ne 'match') { throw 'dotted hypothesis must match' }
        if ((Test-Expect $probe @{ 'ranges.fsext.win32' = 33 }) -ne 'mismatch') { throw 'missing dotted field must not match' }
        if ((Test-Expect $null @{ ok = $true }) -ne 'incomplete') { throw 'missing observation must be incomplete' }
        if ((Test-Expect ([pscustomobject]@{ ok = $false; win32 = 2 }) $null) -ne 'error') { throw 'native error must be error' }
        if ((Test-Expect ([pscustomobject]@{ ok = $true; complete = $false }) @{ ok = $true }) -ne 'error') { throw 'partial must be error' }
        # A usable observation with no hypothesis is recorded, not a match: the
        # observer relies on that for its harness and manifest records.
        if ((Test-Expect ([pscustomobject]@{ ok = $true; complete = $true }) $null) -ne 'recorded') { throw 'no hypothesis must be recorded' }
        $denied = [pscustomobject]@{ ok = $true; opened = $false; win32 = 5 }
        if ((Test-Expect $denied @{ opened = $false; win32 = 32 }) -ne 'unknown') { throw 'access denied must be unknown' }
        $deep = [pscustomobject]@{ ok = $true; list = @([pscustomobject]@{ tokenWin32 = 5 }) }
        if (-not (Test-Denied $deep)) { throw 'nested access denial must be found' }
        if ((Test-Expect ([pscustomobject]@{ ok = $true; state = 'unknown' }) @{ state = 'live' }) -ne 'unknown') { throw 'unknown state must be unknown' }
        if ((Test-Expect ([pscustomobject]@{ ok = $true; opened = $false }) @{ opened = $false }) -ne 'match') { throw 'false hypothesis must match false' }
        if ((Get-Dotted $probe 'ranges.rust.win32') -ne 33) { throw 'dotted lookup must reach a nested value' }
        if ($null -ne (Get-Dotted $probe 'ranges.absent.win32')) { throw 'a missing dotted path must be null' }
        $a = [pscustomobject]@{ 'x.ps1' = 'aa'; 'y.cs' = 'bb' }
        if (-not (Test-SameDigests $a ([pscustomobject]@{ 'y.cs' = 'bb'; 'x.ps1' = 'aa' }))) { throw 'equal digests must compare equal' }
        if (Test-SameDigests $a ([pscustomobject]@{ 'x.ps1' = 'aa'; 'y.cs' = 'BB' })) { throw 'digests compare case-sensitively' }
        if (Test-SameDigests $a ([pscustomobject]@{ 'x.ps1' = 'aa' })) { throw 'missing digest must differ' }
    }
}

# ---- This script's own path and TEMP gate, before Add-Type ---------------
# The compiler Add-Type starts writes its temporaries into %TEMP%, so %TEMP%
# and this directory must clear the real-home boundary first. The helpers used
# here are the observer's own, taken from its syntax tree above.
function Assert-PathGate {
    if (-not (Get-Command Test-PathGateSafe -ErrorAction SilentlyContinue)) { throw 'the path gate helpers were not loaded' }
    $userProfile = $env:USERPROFILE
    if (-not $userProfile -or -not (Test-LocalPathSpelling $userProfile)) { throw 'USERPROFILE is unset or not an accepted absolute local path' }
    $userCodexHome = [IO.Path]::GetFullPath((Join-Path $userProfile '.codex'))
    $envCodexHome = $null
    if ($env:CODEX_HOME) { $envCodexHome = [IO.Path]::GetFullPath($env:CODEX_HOME) }
    $tempRoot = $null
    if ($env:TEMP) { $tempRoot = [IO.Path]::GetFullPath($env:TEMP) }
    if (-not $tempRoot) { throw 'TEMP is not set' }
    $tempReason = Test-PathGateSafe $tempRoot $userCodexHome $envCodexHome $false
    if ($tempReason) { throw "TEMP is not usable as a compiler scratch root ($tempReason)" }
    $here = [IO.Path]::GetFullPath($PSScriptRoot)
    $hereReason = Test-PathGateSafe $here $userCodexHome $envCodexHome $false
    if ($hereReason) { throw "the harness directory is not usable ($hereReason)" }
    [pscustomobject]@{ tempRoot = $tempRoot; scriptRoot = $here; userCodexHome = $userCodexHome; envCodexHome = $envCodexHome }
}

$gateOk = $false
try {
    $PathGate = Assert-PathGate
    Report ('path gate ok: TEMP ' + $PathGate.tempRoot + ' is outside every real Codex home')
    $gateOk = $true
} catch {
    Fail ('path gate error: ' + $_.Exception.Message)
}

if ($gateOk) {
    try {
        Add-Type -Path (Join-Path $PSScriptRoot 'WinObserver.cs')
        $methods = [WinObserver].GetMethods() | Select-Object -ExpandProperty Name
        foreach ($m in 'SelfToken', 'ProcessIdentity', 'Identity', 'Ancestry', 'ShareProbe', 'GuardedRangeProbe', 'RmList', 'DirFileId', 'SetRoot') {
            if ($methods -notcontains $m) { throw "missing method $m" }
        }
        Report 'compile ok: WinObserver.cs (no method called)'
    } catch {
        Fail ('compile error: ' + $_.Exception.Message)
    }
} else {
    Report 'skipped the compile check because the path gate failed'
}

if ($failed) { exit 1 }
exit 0
