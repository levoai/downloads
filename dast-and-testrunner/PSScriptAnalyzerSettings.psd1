@{
    Severity     = @('Warning', 'Error')
    # Interactive installer: Write-Host is the intended output, the "unused" parameters are
    # read from nested functions, and the function names are internal.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSReviewUnusedParameter',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns'
    )
}
