Describe 'Invoke-TechAgent synthetic snapshot reconciliation fixture' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'Support\Invoke-TechAgent.E2EFixture.ps1')
        $script:fixtureAssemblyRoot = Join-Path $PSScriptRoot '..\src\TechToolbox.Agent\bin\Release\net8.0'
        $script:agentAssembly = Join-Path $script:fixtureAssemblyRoot 'TechToolbox.Agent.dll'
        $script:semanticAssembly = Join-Path $script:fixtureAssemblyRoot 'TechToolbox.Agent.SemanticIndexing.dll'
    }

    It 'constructs and proves one isolated production-compatible planned reconciliation row' {
        $root = $null
        $priorLocalData = [Environment]::GetEnvironmentVariable('TT_LocalDataRoot', 'Process')
        $priorLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
        $assemblyResolver = $null
        try {
            $root = New-TTE2EOwnedRoot -Prefix 'tt-reconciliation-e2e-'
            $sourceRoot = Join-Path $root 'sources'
            $localDataRoot = Join-Path $root 'local-data'
            [void](New-Item -ItemType Directory -Path $sourceRoot -Force)
            [void](New-Item -ItemType Directory -Path $localDataRoot -Force)
            [Environment]::SetEnvironmentVariable('TT_LocalDataRoot', $localDataRoot, 'Process')
            [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $root 'local-app-data'), 'Process')

            foreach ($assembly in @($script:semanticAssembly, $script:agentAssembly)) {
                if (!(Test-Path -LiteralPath $assembly -PathType Leaf)) { throw "Production assembly unavailable: $assembly" }
                [void][Reflection.Assembly]::LoadFrom([IO.Path]::GetFullPath($assembly))
            }
            $oldContent = 'Synthetic Scenario A predecessor snapshot with a canonical chunk identity.'
            $changedContent = 'Synthetic Scenario A changed approved snapshot with a distinct canonical chunk identity.'
            $sourcePath = Join-Path $sourceRoot 'scenario-a.txt'
            [IO.File]::WriteAllText($sourcePath, $oldContent, [Text.UTF8Encoding]::new($false))
            $sourceExisted = Test-Path -LiteralPath $sourcePath -PathType Leaf

            $retrieval = [TechToolbox.Agent.Configuration.AgentRetrievalConfiguration]::new()
            $retrieval.Directories = [Collections.Generic.List[string]]::new()
            $retrieval.Directories.Add($sourceRoot)
            $retrieval.AllowedFileExtensions = [Collections.Generic.List[string]]::new()
            $retrieval.AllowedFileExtensions.Add('.txt')
            $options = [TechToolbox.Agent.SemanticIndexing.Ingestion.SourceDiscoveryOptions]::FromRetrievalConfiguration($retrieval, [string[]]@($sourceRoot))
            $candidate = [TechToolbox.Agent.SemanticIndexing.Ingestion.BoundedSourceDiscoverer]::new($options).Discover() | Select-Object -First 1
            if (!$candidate) { throw 'Synthetic source was not discovered.' }
            $loader = [TechToolbox.Agent.SemanticIndexing.Ingestion.FileSourceDocumentLoader]::new($options)
            $predecessorSnapshot = [TechToolbox.Agent.Retrieval.CanonicalSourceSnapshot]::FromSource($loader.Load($candidate))
            $sourceId = $predecessorSnapshot.Source.SourceId
            $sourceIdToken = $null
            $sourceIdRelativePath = $null
            $sourceIdValid = [TechToolbox.Agent.SemanticIndexing.Ingestion.FileSourceIdentity]::TryParse($sourceId, [ref]$sourceIdToken, [ref]$sourceIdRelativePath)

            $manifests = [TechToolbox.Agent.Retrieval.InMemorySourceIndexManifestStore]::new()
            $dense = [TechToolbox.Agent.Retrieval.InMemoryDenseSourceIndexWriter]::new()
            $lexical = [TechToolbox.Agent.Retrieval.InMemoryLexicalSourceIndexWriter]::new()
            $coordinator = [TechToolbox.Agent.Retrieval.CompositeSourceIndexCoordinator]::new($dense, $lexical, $manifests)
            $legacyEmbedding = [TechToolbox.Agent.Retrieval.DeterministicHashEmbeddingGenerator]::new()
            $legacyVectors = $legacyEmbedding.GenerateBatchAsync([string[]]@($predecessorSnapshot.Chunks | ForEach-Object Text), [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            $indexedChunks = [Collections.Generic.List[TechToolbox.Agent.Retrieval.RetrievalIndexedChunk]]::new()
            for ($index = 0; $index -lt $predecessorSnapshot.Chunks.Count; $index++) {
                $indexedChunks.Add([TechToolbox.Agent.Retrieval.RetrievalIndexedChunk]::new($predecessorSnapshot.Chunks[$index], $legacyVectors[$index]))
            }
            $indexedDocument = [TechToolbox.Agent.Retrieval.RetrievalIndexedDocument]::new($predecessorSnapshot.Source, $indexedChunks)
            $predecessorRequest = [TechToolbox.Agent.Retrieval.SourceIndexRequestAdapter]::Create($indexedDocument,
                $legacyEmbedding.Specification, [TechToolbox.Agent.Retrieval.VersionedLexicalAnalyzer]::CurrentVersion, 'scenario-a-predecessor')
            $predecessorPublication = $coordinator.CoordinateAsync($predecessorRequest).GetAwaiter().GetResult()
            if ($predecessorPublication.Code.ToString() -ne 'Published') { throw "Predecessor publication failed: $($predecessorPublication.Code)" }
            $predecessorManifest = $manifests.ReadCurrentAsync($sourceId).GetAwaiter().GetResult()
            $predecessorDenseBuild = [TechToolbox.Agent.Retrieval.DenseSourceIndexBuildSpecification]::new(
                $predecessorManifest.DenseBuild, $legacyEmbedding.Specification.ModelId, $legacyEmbedding.Specification.VectorDimension)
            $predecessorLexicalBuild = [TechToolbox.Agent.Retrieval.LexicalSourceIndexBuildSpecification]::new(
                $predecessorManifest.LexicalBuild, [TechToolbox.Agent.Retrieval.VersionedLexicalAnalyzer]::CurrentVersion)
            $denseVerification = $dense.VerifyGenerationAsync($predecessorSnapshot,
                $predecessorManifest.DenseBuild.GenerationId, $predecessorDenseBuild).GetAwaiter().GetResult()
            $lexicalVerification = $lexical.VerifyGenerationAsync($predecessorSnapshot,
                $predecessorManifest.LexicalBuild.GenerationId, $predecessorLexicalBuild).GetAwaiter().GetResult()
            if (!$denseVerification.IsValid) { throw 'Predecessor dense generation verification failed.' }
            if (!$lexicalVerification.IsValid) { throw 'Predecessor lexical generation verification failed.' }

            [IO.File]::WriteAllText($sourcePath, $changedContent, [Text.UTF8Encoding]::new($false))
            $changedCandidate = [TechToolbox.Agent.SemanticIndexing.Ingestion.BoundedSourceDiscoverer]::new($options).Discover() | Select-Object -First 1
            $approvedSnapshot = [TechToolbox.Agent.Retrieval.CanonicalSourceSnapshot]::FromSource($loader.Load($changedCandidate))
            if ($predecessorSnapshot.Identity.ContentHash -eq $approvedSnapshot.Identity.ContentHash) { throw 'Changed approved snapshot did not differ from predecessor.' }

            $providerHttpClient = [Net.Http.HttpClient]::new()
            $provider = [TechToolbox.Agent.Retrieval.OllamaSemanticEmbeddingProvider]::new(
                $providerHttpClient, 'http://127.0.0.1:11434', 'reconciliation-fixture-model',
                'sha256:fixture-model-v1', 3, [TimeSpan]::FromSeconds(2))
            $service = [TechToolbox.Agent.Retrieval.SemanticDenseRebuildService]::new($provider, $manifests, $coordinator,
                [string[]]@($sourceRoot), [TechToolbox.Agent.Retrieval.VersionedLexicalAnalyzer]::CurrentVersion, $dense, $lexical)
            $orchestrator = [TechToolbox.Agent.Retrieval.SemanticDenseRebuildOrchestrator]::new($service, $manifests,
                $retrieval, [string[]]@($sourceRoot), $provider.Specification, 'http://127.0.0.1:11434')
            $plan = $orchestrator.PlanSnapshotReconciliationAsync([string[]]@($sourceId)).GetAwaiter().GetResult()
            $artifactPath = [IO.Path]::GetFullPath($plan.ArtifactLocation)
            $artifactBytes = [IO.File]::ReadAllBytes($artifactPath)
            $artifactOptions = [Text.Json.JsonSerializerOptions]::new()
            $artifactOptions.PropertyNameCaseInsensitive = $true
            $artifactOptions.Converters.Add([Text.Json.Serialization.JsonStringEnumConverter]::new())
            $artifact = [Text.Json.JsonSerializer]::Deserialize($artifactBytes,
                [TechToolbox.Agent.Retrieval.SemanticSnapshotReconciliationPlanArtifact], $artifactOptions)
            $artifactDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($artifactBytes))
            $row = @($artifact.Outcomes)
            if ($artifactBytes.Length -eq 0 -or $artifactDigest -cne $plan.ArtifactSha256) { throw 'Persisted plan artifact digest mismatch.' }
            if ($artifact.PlanRunId -cne $plan.PlanRunId -or [guid]::ParseExact($artifact.PlanRunId, 'N') -eq [guid]::Empty) { throw 'PlanRunId is invalid or mismatched.' }
            if ($artifact.RequestedCount -ne 1 -or $artifact.PlannedCount -ne 1 -or $row.Count -ne 1) { throw 'Plan artifact does not contain exactly one planned outcome.' }
            if ($row[0].Status -cne 'planned' -or $row[0].SourceId -cne $sourceId) { throw 'Plan row is not the single requested PLANNED source.' }
            if ($row[0].ApprovedSnapshotIdentity.ContentHash -cne $approvedSnapshot.Identity.ContentHash) { throw 'Plan row does not bind the changed approved snapshot.' }
            if (($row[0].PredecessorManifestRevision -ne $predecessorManifest.Revision) -or
                ($row[0].PredecessorDenseGenerationId -cne $predecessorManifest.DenseBuild.GenerationId) -or
                ($row[0].PredecessorLexicalGenerationId -cne $predecessorManifest.LexicalBuild.GenerationId)) { throw 'Plan row does not bind the exact predecessor identity.' }
            if (($row[0].RequestedEmbeddingSpecificationFingerprint -cne $provider.Specification.Fingerprint) -or
                ($row[0].ApprovedPlan.TargetSpecificationFingerprint -cne $provider.Specification.Fingerprint)) { throw 'Plan row does not bind the deterministic target embedding identity.' }
            if ((!$artifact.ExecutionRequiresExplicitApproval) -or (!$row[0].NewDenseGenerationRequired) -or (!$row[0].NewLexicalGenerationRequired) -or
                ($row[0].ApprovedPlan.ReusesLexicalGeneration)) { throw 'Plan does not require explicit approval or both distinct generations.' }
            if (!$row[0].ApprovedPlan.DryRun -or $row[0].ApprovedPlan.TargetGenerationId -eq $predecessorManifest.DenseBuild.GenerationId) { throw 'Target dense generation identity is not a distinct production plan target.' }
            $approval = [ordered]@{ planRunId = $plan.PlanRunId; artifactSha256 = $plan.ArtifactSha256; explicitlyApproved = $true } | ConvertTo-Json -Compress
            $approvalObject = $approval | ConvertFrom-Json
            if (!$approvalObject.explicitlyApproved -or $approvalObject.planRunId -cne $plan.PlanRunId -or $approvalObject.artifactSha256 -cne $plan.ArtifactSha256) { throw 'Synthetic production approval envelope is not exact.' }

            $writablePaths = @($sourcePath, $artifactPath, (Join-Path $localDataRoot 'Artifacts\semantic-indexing'))
            foreach ($path in $writablePaths) { Assert-TTE2EPathUnderRoot -Path $path -Root $root }
            $predecessorReadable = $null -ne $predecessorManifest -and $predecessorManifest.State.ToString() -eq 'Committed'
            $denseReadable = $denseVerification.IsValid
            $lexicalReadable = $lexicalVerification.IsValid
            $artifactReopened = $null -ne $artifact -and (Test-Path -LiteralPath $artifactPath -PathType Leaf)

            $sourceExisted | Should -BeTrue
            $sourceIdValid | Should -BeTrue
            $predecessorReadable | Should -BeTrue
            $denseReadable | Should -BeTrue
            $lexicalReadable | Should -BeTrue
            ($predecessorSnapshot.Identity.ContentHash -cne $approvedSnapshot.Identity.ContentHash) | Should -BeTrue
            $artifactReopened | Should -BeTrue
            $artifactDigest | Should -BeExactly $plan.ArtifactSha256
            $row.Count | Should -Be 1
            $row[0].Status | Should -BeExactly 'planned'
            $row[0].ApprovedSnapshotIdentity.ContentHash | Should -BeExactly $approvedSnapshot.Identity.ContentHash
            $row[0].PredecessorManifestRevision | Should -Be $predecessorManifest.Revision
            $row[0].PredecessorDenseGenerationId | Should -BeExactly $predecessorManifest.DenseBuild.GenerationId
            $row[0].PredecessorLexicalGenerationId | Should -BeExactly $predecessorManifest.LexicalBuild.GenerationId
            $row[0].ApprovedPlan.TargetSpecificationFingerprint | Should -BeExactly $provider.Specification.Fingerprint
            $row[0].ApprovedPlan.TargetGenerationId | Should -Not -BeNullOrEmpty
            $approvalObject.explicitlyApproved | Should -BeTrue
            foreach ($path in $writablePaths) { { Assert-TTE2EPathUnderRoot -Path $path -Root $root } | Should -Not -Throw }
            $plan.PublicationOccurred | Should -BeFalse
            (Test-Path -LiteralPath (Join-Path $localDataRoot 'Artifacts\semantic-indexing\Runtime\SemanticSnapshotReconciliation\plans')) | Should -BeTrue

            # Keep the authoritative synthetic fixture alive for the following response-sequence test.
            $script:scenarioAFixtureRoot = $root
            $script:scenarioAApprovedPlanJson = $approval
            $script:scenarioAPlanRunId = $plan.PlanRunId
            $script:scenarioAArtifactSha256 = $plan.ArtifactSha256
            $script:scenarioAArtifactPath = $artifactPath
            $script:scenarioAExecuteToolName = [TechToolbox.Agent.Execution.SourceDiscoveryIngestionToolExecutor]::ExecuteSnapshotReconciliationToolName
        }
        finally {
            if ($providerHttpClient) { $providerHttpClient.Dispose() }
            [Environment]::SetEnvironmentVariable('TT_LocalDataRoot', $priorLocalData, 'Process')
            [Environment]::SetEnvironmentVariable('LOCALAPPDATA', $priorLocalAppData, 'Process')
            if ($root -and $root -cne $script:scenarioAFixtureRoot -and (Test-Path -LiteralPath $root)) { Remove-TTE2EOwnedRoot -Path $root -ExpectedPrefix 'tt-reconciliation-e2e-' }
        }
    }

    It 'reopens a production-persistent worker-compatible Scenario A fixture' {
        $root = $null
        $endpoint = $null
        $http = $null
        $priorLocalData = [Environment]::GetEnvironmentVariable('TT_LocalDataRoot', 'Process')
        $priorLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
        $liveRoot = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'TechToolbox' } else { $null }
        $liveBefore = Get-TTE2EInventory -Root $liveRoot
        try {
            $root = New-TTE2EOwnedRoot -Prefix 'tt-reconciliation-worker-fixture-'
            $localDataRoot = Join-Path (Join-Path $root 'local-app-data') 'TechToolbox'
            $sourceRoot = Join-Path $localDataRoot 'sources'
            [void](New-Item -ItemType Directory -Path $localDataRoot -Force)
            [void](New-Item -ItemType Directory -Path $sourceRoot -Force)
            [Environment]::SetEnvironmentVariable('TT_LocalDataRoot', $localDataRoot, 'Process')
            [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $root 'local-app-data'), 'Process')
            $endpoint = New-TTE2EDeterministicEmbeddingEndpoint
            foreach ($assembly in @($script:semanticAssembly, $script:agentAssembly)) {
                if (!(Test-Path -LiteralPath $assembly -PathType Leaf)) { throw "Production assembly unavailable: $assembly" }
                [void][Reflection.Assembly]::LoadFrom([IO.Path]::GetFullPath($assembly))
            }

            $sourcePath = Join-Path $sourceRoot 'scenario-a-worker.txt'
            $oldContent = 'Synthetic production predecessor snapshot for the worker-compatible persistent fixture.'
            $newContent = 'Synthetic changed approved snapshot for the production-persistent worker fixture.'
            [IO.File]::WriteAllText($sourcePath, $oldContent, [Text.UTF8Encoding]::new($false))
            $retrieval = [TechToolbox.Agent.Configuration.AgentRetrievalConfiguration]::new()
            $retrieval.Directories = [Collections.Generic.List[string]]::new()
            $retrieval.Directories.Add($sourceRoot)
            $retrieval.AllowedFileExtensions = [Collections.Generic.List[string]]::new()
            $retrieval.AllowedFileExtensions.Add('.txt')
            $options = [TechToolbox.Agent.SemanticIndexing.Ingestion.SourceDiscoveryOptions]::FromRetrievalConfiguration($retrieval, [string[]]@($sourceRoot))
            $loader = [TechToolbox.Agent.SemanticIndexing.Ingestion.FileSourceDocumentLoader]::new($options)
            $discoverer = [TechToolbox.Agent.SemanticIndexing.Ingestion.BoundedSourceDiscoverer]::new($options)
            $candidate = $discoverer.Discover() | Select-Object -First 1
            if (!$candidate) { throw 'Synthetic persistent source was not discovered.' }
            $predecessor = [TechToolbox.Agent.Retrieval.CanonicalSourceSnapshot]::FromSource($loader.Load($candidate))
            $sourceId = $predecessor.Source.SourceId
            $token = $null; $relativePath = $null
            if (![TechToolbox.Agent.SemanticIndexing.Ingestion.FileSourceIdentity]::TryParse($sourceId, [ref]$token, [ref]$relativePath)) { throw 'SourceId is not valid v2.' }

            $lifecycle = [TechToolbox.Agent.Retrieval.ProductionSourceIndexLifecycleConfiguration]::CreateDefault()
            foreach ($path in @($lifecycle.ManifestRoot, $lifecycle.DenseRoot, $lifecycle.LexicalRoot)) { Assert-TTE2EPathUnderRoot -Path $path -Root $localDataRoot }
            $manifests = $lifecycle.CreateManifestStore()
            $coordinator = $lifecycle.CreateCoordinator()
            $legacy = [TechToolbox.Agent.Retrieval.DeterministicHashEmbeddingGenerator]::new()
            $vectors = $legacy.GenerateBatchAsync([string[]]@($predecessor.Chunks | ForEach-Object Text), [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            $chunks = [Collections.Generic.List[TechToolbox.Agent.Retrieval.RetrievalIndexedChunk]]::new()
            for ($i = 0; $i -lt $predecessor.Chunks.Count; $i++) { $chunks.Add([TechToolbox.Agent.Retrieval.RetrievalIndexedChunk]::new($predecessor.Chunks[$i], $vectors[$i])) }
            $document = [TechToolbox.Agent.Retrieval.RetrievalIndexedDocument]::new($predecessor.Source, $chunks)
            $request = [TechToolbox.Agent.Retrieval.SourceIndexRequestAdapter]::Create($document, $legacy.Specification,
                [TechToolbox.Agent.Retrieval.VersionedLexicalAnalyzer]::CurrentVersion, 'scenario-a-worker-predecessor')
            $published = $coordinator.CoordinateAsync($request).GetAwaiter().GetResult()
            if ($published.Code.ToString() -ne 'Published') { throw "Persistent predecessor failed: $($published.Code)" }
            $manifest = $manifests.ReadCurrentAsync($sourceId).GetAwaiter().GetResult()
            if (!$manifest -or $manifest.State.ToString() -ne 'Committed') { throw 'Persistent manifest was not committed.' }
            $revision = $manifest.Revision
            $denseId = $manifest.DenseBuild.GenerationId
            $lexicalId = $manifest.LexicalBuild.GenerationId

            [IO.File]::WriteAllText($sourcePath, $newContent, [Text.UTF8Encoding]::new($false))
            $changedCandidate = $discoverer.Discover() | Select-Object -First 1
            $approvedSnapshot = [TechToolbox.Agent.Retrieval.CanonicalSourceSnapshot]::FromSource($loader.Load($changedCandidate))
            if ($approvedSnapshot.Identity.ContentHash -ceq $predecessor.Identity.ContentHash) { throw 'Changed approved snapshot matches predecessor.' }

            $retrieval.SourceIndexLifecycleEnabled = $true
            $retrieval.EmbeddingModel = 'scenario-a-embedding'
            $retrieval.EmbeddingDimension = 3
            $retrieval.EmbeddingEndpoint = $endpoint.Url
            $configuration = [TechToolbox.Agent.Configuration.AgentConfiguration]::new()
            $configuration.LlmProvider = 'openai-compatible'
            $configuration.Retrieval = $retrieval
            $http = [Net.Http.HttpClient]::new()
            $provider = [TechToolbox.Agent.Retrieval.ProductionEmbeddingProviderFactory]::CreateAsync($configuration, $http).GetAwaiter().GetResult()
            $service = $lifecycle.CreateSemanticDenseRebuildService($provider, [string[]]@($sourceRoot))
            $orchestrator = [TechToolbox.Agent.Retrieval.SemanticDenseRebuildOrchestrator]::new($service, $manifests,
                $retrieval, [string[]]@($sourceRoot), $provider.Specification, $endpoint.Url)
            $plan = $orchestrator.PlanSnapshotReconciliationAsync([string[]]@($sourceId)).GetAwaiter().GetResult()
            $artifactPath = [IO.Path]::GetFullPath($plan.ArtifactLocation)
            $artifactBytes = [IO.File]::ReadAllBytes($artifactPath)
            $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($artifactBytes))
            $jsonOptions = [Text.Json.JsonSerializerOptions]::new()
            $jsonOptions.PropertyNameCaseInsensitive = $true
            $jsonOptions.Converters.Add([Text.Json.Serialization.JsonStringEnumConverter]::new())
            $artifact = [Text.Json.JsonSerializer]::Deserialize($artifactBytes, [TechToolbox.Agent.Retrieval.SemanticSnapshotReconciliationPlanArtifact], $jsonOptions)
            $row = @($artifact.Outcomes)
            if ($digest -cne $plan.ArtifactSha256 -or $artifact.PlanRunId -cne $plan.PlanRunId) { throw 'Persisted PlanArtifact digest or PlanRunId mismatch.' }
            if ($artifact.RequestedCount -ne 1 -or $artifact.PlannedCount -ne 1 -or $row.Count -ne 1 -or $row[0].Status -cne 'planned') { throw 'Artifact does not contain exactly one PLANNED row.' }
            if ($row[0].SourceId -cne $sourceId -or $row[0].PredecessorManifestRevision -ne $revision) { throw 'Plan row source or predecessor revision mismatch.' }
            if ($row[0].PredecessorDenseGenerationId -cne $denseId -or $row[0].PredecessorLexicalGenerationId -cne $lexicalId) { throw 'Plan row predecessor generation mismatch.' }
            if ($row[0].ApprovedSnapshotIdentity.ContentHash -cne $approvedSnapshot.Identity.ContentHash -or $row[0].ApprovedSnapshotIdentity.ContentHash -ceq $predecessor.Identity.ContentHash) { throw 'Approved snapshot binding mismatch.' }
            if ($row[0].RequestedEmbeddingSpecificationFingerprint -cne $provider.Specification.Fingerprint -or $row[0].ApprovedPlan.TargetSpecificationFingerprint -cne $provider.Specification.Fingerprint) { throw 'Approved embedding fingerprint mismatch.' }
            if (!$artifact.ExecutionRequiresExplicitApproval -or $artifact.PublicationOccurred -or !$row[0].NewDenseGenerationRequired -or !$row[0].NewLexicalGenerationRequired -or $row[0].ApprovedPlan.ReusesLexicalGeneration) { throw 'Plan authority or generation change requirements mismatch.' }
            if ($artifact.SemanticEmbeddingEndpoint -cne $endpoint.Url) { throw 'Plan endpoint is not the harness-owned embedding listener.' }
            $retrievalConfigPath = Join-Path $localDataRoot 'worker-runtime-retrieval-config.json'
            [IO.File]::WriteAllText($retrievalConfigPath, ($retrieval | ConvertTo-Json -Depth 12 -Compress), [Text.UTF8Encoding]::new($false))
            Assert-TTE2EPathUnderRoot -Path $sourcePath -Root $localDataRoot
            foreach ($path in @($artifactPath, $retrievalConfigPath)) { Assert-TTE2EPathUnderRoot -Path $path -Root $localDataRoot }

            $manifests = $null; $coordinator = $null; $service = $null; $orchestrator = $null; $lifecycle = $null; $provider = $null
            [GC]::Collect(); [GC]::WaitForPendingFinalizers()

            $freshLifecycle = [TechToolbox.Agent.Retrieval.ProductionSourceIndexLifecycleConfiguration]::CreateDefault()
            foreach ($path in @($freshLifecycle.ManifestRoot, $freshLifecycle.DenseRoot, $freshLifecycle.LexicalRoot, $artifactPath, $retrievalConfigPath)) { Assert-TTE2EPathUnderRoot -Path $path -Root $localDataRoot }
            $freshManifests = $freshLifecycle.CreateManifestStore()
            $freshManifest = $freshManifests.ReadCurrentAsync($sourceId).GetAwaiter().GetResult()
            if (!$freshManifest -or $freshManifest.Revision -ne $revision -or $freshManifest.DenseBuild.GenerationId -cne $denseId -or $freshManifest.LexicalBuild.GenerationId -cne $lexicalId) { throw 'Fresh lifecycle could not reopen exact predecessor manifest identity.' }
            $freshDense = $freshLifecycle.CreateDenseWriter()
            $freshLexical = $freshLifecycle.CreateLexicalWriter()
            $denseBuild = [TechToolbox.Agent.Retrieval.DenseSourceIndexBuildSpecification]::new($freshManifest.DenseBuild, $legacy.Specification.ModelId, $legacy.Specification.VectorDimension)
            $lexicalBuild = [TechToolbox.Agent.Retrieval.LexicalSourceIndexBuildSpecification]::new($freshManifest.LexicalBuild, [TechToolbox.Agent.Retrieval.VersionedLexicalAnalyzer]::CurrentVersion)
            $denseVerification = $freshDense.VerifyGenerationAsync($predecessor, $denseId, $denseBuild).GetAwaiter().GetResult()
            $lexicalVerification = $freshLexical.VerifyGenerationAsync($predecessor, $lexicalId, $lexicalBuild).GetAwaiter().GetResult()
            if (!$denseVerification.IsValid) { throw "Fresh dense verification failed: $($denseVerification.Issues)" }
            if (!$lexicalVerification.IsValid) { throw "Fresh lexical verification failed: $($lexicalVerification.Issues)" }
            $reopenedBytes = [IO.File]::ReadAllBytes($artifactPath)
            $reopenedDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($reopenedBytes))
            if ($reopenedDigest -cne $plan.ArtifactSha256 -or [Convert]::ToBase64String($reopenedBytes) -cne [Convert]::ToBase64String($artifactBytes)) { throw 'Artifact bytes changed on reopen.' }
            $freshArtifact = [Text.Json.JsonSerializer]::Deserialize($reopenedBytes, [TechToolbox.Agent.Retrieval.SemanticSnapshotReconciliationPlanArtifact], $jsonOptions)
            if ($freshArtifact.PlanRunId -cne $plan.PlanRunId -or $freshArtifact.Outcomes.Count -ne 1 -or $freshArtifact.Outcomes[0].SourceId -cne $freshManifest.SourceId) { throw 'Fresh artifact identity does not match persistent manifest.' }

            $freshRetrieval = [TechToolbox.Agent.Configuration.AgentRetrievalConfiguration]::new()
            $freshRetrieval.EmbeddingModel = 'scenario-a-embedding'
            $freshRetrieval.EmbeddingDimension = 3
            $freshRetrieval.EmbeddingEndpoint = $freshArtifact.SemanticEmbeddingEndpoint
            $freshConfiguration = [TechToolbox.Agent.Configuration.AgentConfiguration]::new()
            $freshConfiguration.LlmProvider = 'openai-compatible'
            $freshConfiguration.Retrieval = $freshRetrieval
            $freshProvider = [TechToolbox.Agent.Retrieval.ProductionEmbeddingProviderFactory]::CreateAsync($freshConfiguration, $http).GetAwaiter().GetResult()
            if ($freshProvider.Specification.Fingerprint -cne $freshArtifact.RequestedEmbeddingSpecificationFingerprint) { throw 'Fresh production provider fingerprint does not match plan.' }
            $probeTexts = [Collections.Generic.List[string]]::new()
            $probeTexts.Add('synthetic worker embedding protocol probe')
            $probe = $freshProvider.GenerateBatchAsync($probeTexts, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if ($probe.Count -ne 1 -or $probe[0].Count -ne 3) { throw 'Deterministic endpoint returned incompatible embeddings.' }
            if ($endpoint.TagCount -ne 2 -or $endpoint.EmbedCount -ne 1 -or $endpoint.RequestCount -ne 3) { throw 'Unexpected isolated provider endpoint request counters.' }
            if ($freshArtifact.SemanticEmbeddingEndpoint -match '127\\.0\\.0\\.1:11434|localhost:11434') { throw 'Fixture endpoint resolved to the normal Ollama endpoint.' }

            $sourceExisted = Test-Path -LiteralPath $sourcePath -PathType Leaf
            $sourceExisted | Should -BeTrue
            $freshManifest.Revision | Should -Be $revision
            $denseVerification.IsValid | Should -BeTrue
            $lexicalVerification.IsValid | Should -BeTrue
            $reopenedDigest | Should -BeExactly $plan.ArtifactSha256
            $freshArtifact.PlanRunId | Should -BeExactly $plan.PlanRunId
            $freshArtifact.Outcomes.Count | Should -Be 1
            $freshArtifact.Outcomes[0].Status | Should -BeExactly 'planned'
            $freshArtifact.Outcomes[0].PredecessorManifestRevision | Should -Be $revision
            $freshProvider.Specification.Fingerprint | Should -BeExactly $freshArtifact.RequestedEmbeddingSpecificationFingerprint
            $plan.PublicationOccurred | Should -BeFalse
            Assert-TTE2EInventoryUnchanged -Before $liveBefore -After (Get-TTE2EInventory -Root $liveRoot)

            # Retain this production-persistent fixture for the actual governed detached-worker scenario.
            $script:scenarioAWorkerFixtureRoot = $root
            $script:scenarioAWorkerLocalDataRoot = $localDataRoot
            $script:scenarioAWorkerSourceRoot = $sourceRoot
            $script:scenarioAWorkerSourcePath = $sourcePath
            $script:scenarioAWorkerEndpoint = $endpoint
            $script:scenarioAWorkerPlan = $plan
            $script:scenarioAWorkerArtifactPath = $artifactPath
            $script:scenarioAWorkerArtifact = $freshArtifact
            $script:scenarioAWorkerRetrievalJson = [IO.File]::ReadAllText($retrievalConfigPath)
            $script:scenarioAWorkerPredecessor = $predecessor
            $script:scenarioAWorkerPredecessorManifest = $manifest
            $script:scenarioAWorkerApprovedSnapshot = $approvedSnapshot
            $script:scenarioAWorkerManifestRevision = $revision
            $script:scenarioAWorkerDenseGenerationId = $denseId
            $script:scenarioAWorkerLexicalGenerationId = $lexicalId
            $script:scenarioAWorkerEmbeddingFingerprint = $provider.Specification.Fingerprint
            $script:scenarioAWorkerInitialEndpointRequests = $endpoint.RequestCount
            $script:scenarioAWorkerInitialTags = $endpoint.TagCount
            $script:scenarioAWorkerInitialEmbeds = $endpoint.EmbedCount
            $script:scenarioAWorkerInitialRequestEvidence = @($endpoint.RequestEvidence)
            $script:scenarioAWorkerInitialDenseGenerations = @((Get-ChildItem -LiteralPath $freshLifecycle.DenseRoot -Directory -ErrorAction SilentlyContinue).Name)
            $script:scenarioAWorkerInitialLexicalGenerations = @((Get-ChildItem -LiteralPath $freshLifecycle.LexicalRoot -Directory -ErrorAction SilentlyContinue).Name)
            $script:scenarioAFixtureRoot = $root
            $script:scenarioAApprovedPlanJson = [ordered]@{ planRunId = $plan.PlanRunId; artifactSha256 = $plan.ArtifactSha256; explicitlyApproved = $true } | ConvertTo-Json -Compress
            $script:scenarioAPlanRunId = $plan.PlanRunId
            $script:scenarioAArtifactSha256 = $plan.ArtifactSha256
            $script:scenarioAArtifactPath = $artifactPath
            $script:scenarioAExecuteToolName = [TechToolbox.Agent.Execution.SourceDiscoveryIngestionToolExecutor]::ExecuteSnapshotReconciliationToolName
        }
        finally {
            if ($http) { $http.Dispose() }
            if ($root -cne $script:scenarioAWorkerFixtureRoot -and $endpoint) { $endpoint.Dispose() }
            [Environment]::SetEnvironmentVariable('TT_LocalDataRoot', $priorLocalData, 'Process')
            [Environment]::SetEnvironmentVariable('LOCALAPPDATA', $priorLocalAppData, 'Process')
            if ($root -and $root -cne $script:scenarioAWorkerFixtureRoot -and (Test-Path -LiteralPath $root)) { Remove-TTE2EOwnedRoot -Path $root -ExpectedPrefix 'tt-reconciliation-worker-fixture-' }
            Assert-TTE2EInventoryUnchanged -Before $liveBefore -After (Get-TTE2EInventory -Root $liveRoot)
        }
    }

    It 'constructs and validates the deterministic two-turn Scenario A model-response fixture' {
        if (!$script:scenarioAFixtureRoot -or !(Test-Path -LiteralPath $script:scenarioAArtifactPath -PathType Leaf)) {
            throw 'The authoritative synthetic Scenario A fixture is unavailable.'
        }

        function Invoke-TTE2EReconciliationTestRequest {
            param([Parameter(Mandatory)][string]$Url)
            $client = [Net.Http.HttpClient]::new()
            try {
                $response = $client.PostAsync($Url + '/v1/chat/completions', [Net.Http.StringContent]::new('{"request":true}', [Text.Encoding]::UTF8, 'application/json')).GetAwaiter().GetResult()
                $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $body }
            }
            finally { $client.Dispose() }
        }

        $decisionOne = [ordered]@{
            needsTool = $true
            toolName = $script:scenarioAExecuteToolName
            toolArgs = [ordered]@{ approvedPlanJson = $script:scenarioAApprovedPlanJson }
            reason = 'Execute the exact reviewed synthetic reconciliation plan.'
        } | ConvertTo-Json -Compress -Depth 8
        $decisionTwo = [ordered]@{
            needsTool = $false
            finalAnswer = 'SCENARIO_A_LAUNCH_OK'
            reason = 'The tool result confirms completion.'
        } | ConvertTo-Json -Compress -Depth 8
        $responseOne = [ordered]@{ choices = @([ordered]@{ index = 0; message = [ordered]@{ role = 'assistant'; content = $decisionOne }; finish_reason = 'stop' }) } | ConvertTo-Json -Compress -Depth 8
        $responseTwo = [ordered]@{ choices = @([ordered]@{ index = 0; message = [ordered]@{ role = 'assistant'; content = $decisionTwo }; finish_reason = 'stop' }) } | ConvertTo-Json -Compress -Depth 8

        $parsedOne = $null
        $parsedTwo = $null
        [TechToolbox.Agent.Core.JsonHelpers]::TryParseDecision($decisionOne, [ref]$parsedOne) | Should -BeTrue
        [TechToolbox.Agent.Core.JsonHelpers]::TryParseDecision($decisionTwo, [ref]$parsedTwo) | Should -BeTrue
        $parsedOne.NeedsTool | Should -BeTrue
        $parsedOne.ToolName | Should -BeExactly $script:scenarioAExecuteToolName
        $parsedOne.ToolArgs['approvedPlanJson'] | Should -BeExactly $script:scenarioAApprovedPlanJson
        @($parsedOne.ToolArgs.Keys) | Should -Be @('approvedPlanJson')
        $parsedTwo.NeedsTool | Should -BeFalse
        $parsedTwo.FinalAnswer | Should -BeExactly 'SCENARIO_A_LAUNCH_OK'

        $serializedDecisionFixture = $responseOne + $responseTwo
        foreach ($forbidden in @('__destructive_approval_token', 'authorizationContext', 'artifactPath', 'sourceIds', 'credential', $script:scenarioAArtifactPath, 'C:\\repos\\TechToolbox\\data')) {
            $serializedDecisionFixture | Should -Not -Match ([regex]::Escape($forbidden))
        }
        $approvalObject = $script:scenarioAApprovedPlanJson | ConvertFrom-Json
        @($approvalObject.PSObject.Properties.Name | Sort-Object) | Should -Be @('artifactSha256', 'explicitlyApproved', 'planRunId')
        $approvalObject.planRunId | Should -BeExactly $script:scenarioAPlanRunId
        $approvalObject.artifactSha256 | Should -BeExactly $script:scenarioAArtifactSha256
        $approvalObject.explicitlyApproved | Should -BeTrue
        (Get-FileHash -LiteralPath $script:scenarioAArtifactPath -Algorithm SHA256).Hash | Should -BeExactly $script:scenarioAArtifactSha256

        $script:scenarioAResponseBodies = @($responseOne, $responseTwo)
        $endpoint = New-TTE2ELoopbackEndpoint -ResponseBodies $script:scenarioAResponseBodies
        try {
            $first = Invoke-TTE2EReconciliationTestRequest -Url $endpoint.Url
            $second = Invoke-TTE2EReconciliationTestRequest -Url $endpoint.Url
            $first.StatusCode | Should -Be 200
            $second.StatusCode | Should -Be 200
            $first.Body | Should -BeExactly $responseOne
            $second.Body | Should -BeExactly $responseTwo
            $endpoint.RequestCount | Should -Be 2
            @($endpoint.ResponseIndices) | Should -Be @(0, 1)
            @($endpoint.RequestOrder) | Should -Be @(1, 2)
            $endpoint.SequenceExhausted | Should -BeFalse
        }
        finally { Stop-TTE2ELoopbackEndpoint -Endpoint $endpoint }
    }

    It 'performs one governed durable Scenario A launch through real Invoke-TechAgent' {
        if (!$script:scenarioAFixtureRoot -or !(Test-Path -LiteralPath $script:scenarioAArtifactPath -PathType Leaf) -or !$script:scenarioAResponseBodies) {
            throw 'The authoritative Scenario A plan and deterministic response sequence are unavailable.'
        }
        $root = $script:scenarioAWorkerFixtureRoot
        $process = $null
        $processTicks = 0L
        $endpoint = $null
        $evidencePath = $null
        $liveRoot = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'TechToolbox' } else { $null }
        $liveBefore = Get-TTE2EInventory -Root $liveRoot
        if (!$root -or !$script:scenarioAWorkerEndpoint) { throw 'Persistent production worker fixture is unavailable.' }
        try {
            $evidencePath = Join-Path $root 'evidence.json'
            $endpoint = New-TTE2ELoopbackEndpoint -ResponseBodies $script:scenarioAResponseBodies
            $manifest = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\TechToolbox.psd1'))
            $pwsh = Resolve-TTE2EPwsh
            $code = @'
$ErrorActionPreference = 'Stop'
$root = $env:TT_TEST_ROOT
$life = Join-Path $root 'lifecycle.txt'
function Mark([string]$value) { [IO.File]::AppendAllText($life, $value + [Environment]::NewLine) }
$local = Join-Path $root 'local-app-data'
[void](New-Item -ItemType Directory -Path $local -Force)
$env:LOCALAPPDATA = $local
foreach ($name in @('TT_Home','TT_LocalDataRoot','TT_ModuleRoot','TT_LogsRoot','TT_ExportsRoot','TT_AGENT_FILESYSTEM_ROOT','TT_AGENT_ALLOWED_PATH_ROOTS','TT_AGENT_LOCAL_MCP_ADAPTER_PATH','TT_APPROVAL_RESPONSE','TT_AGENT_APPROVAL_RESPONSE','TT_AGENT_LLM_API_KEY','TT_AGENT_RETRIEVAL_CONFIG_JSON','TT_AGENT_SEMANTIC_REBUILD_OLLAMA_ENDPOINT')) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
$env:TT_LocalDataRoot = $env:TT_TEST_WORKER_LOCAL_DATA_ROOT
$env:TT_AGENT_ALLOWED_PATH_ROOTS = $env:TT_TEST_WORKER_ALLOWED_ROOTS
$env:TT_AGENT_RETRIEVAL_CONFIG_JSON = $env:TT_TEST_WORKER_RETRIEVAL_CONFIG
$env:TT_AGENT_SEMANTIC_REBUILD_OLLAMA_ENDPOINT = $env:TT_TEST_WORKER_EMBEDDING_ENDPOINT
$env:TT_AGENT_LLM_API_KEY = 'scenario-a-loopback-key'
$config = Join-Path $local 'TechToolbox\Config'
[void](New-Item -ItemType Directory -Path $config -Force)
[IO.File]::WriteAllText((Join-Path $config 'config.secrets.json'), '{}', [Text.Encoding]::UTF8)
$agentSettings = [ordered]@{ orchestratorRunDeadlineSeconds = 60; retrieval = ($env:TT_TEST_WORKER_RETRIEVAL_CONFIG | ConvertFrom-Json) }
$userConfig = [ordered]@{ settings = [ordered]@{ agent = $agentSettings } }
[IO.File]::WriteAllText((Join-Path $config 'config.json'), ($userConfig | ConvertTo-Json -Depth 12 -Compress), [Text.Encoding]::UTF8)
$module = $null
$statusPath = $null
$invocationOutput = ''
$approvalCalls = [hashtable]::Synchronized(@{ Count = 0 })
try {
    Mark 'module-import-started'
    $module = Import-Module $env:TT_TEST_MANIFEST -Force -PassThru -ErrorAction Stop
    Mark 'module-import-completed'
    $tt = $module.SessionState.PSVariable.GetValue('TT')
    $runtime = [IO.Path]::GetFullPath((Join-Path $module.ModuleBase 'src\TechToolbox.Agent\bin\Release\net8.0\TechToolbox.Agent.dll'))
    if (!(Test-Path -LiteralPath $runtime -PathType Leaf) -or $runtime -match '[\\/]bin[\\/]Debug[\\/]') { throw "Non-Debug Release runtime unavailable: $runtime" }
    # The published output can be locked by unrelated pre-existing PowerShell hosts; use this freshly built Release assembly directly.
    & $module {
        param($assemblyPath)
        $literal = $assemblyPath.Replace("'", "''")
        Set-Item -Path Function:\Resolve-TTAgentRuntimeAssemblyPath -Value ([scriptblock]::Create("param([string]`$ModuleRoot) return '$literal'"))
    } $runtime
    $expectedRuntime = $runtime
    $localDataRoot = [IO.Path]::GetFullPath([string]$tt.LocalDataRoot)
    $rootPrefix = [IO.Path]::GetFullPath($root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (!$localDataRoot.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "LocalDataRoot escaped the isolated root: $localDataRoot" }

    # Transfer the proven persisted artifact bytes into the isolated LocalDataRoot without changing the approved content.
    $planDirectory = Join-Path $localDataRoot 'Artifacts\semantic-indexing\Runtime\SemanticSnapshotReconciliation\plans'
    [void](New-Item -ItemType Directory -Path $planDirectory -Force)
    $isolatedArtifact = Join-Path $planDirectory ($env:TT_TEST_PLAN_RUN_ID + '.json')
    [IO.File]::WriteAllBytes($isolatedArtifact, [IO.File]::ReadAllBytes($env:TT_TEST_FIXTURE_ARTIFACT))
    $isolatedDigest = (Get-FileHash -LiteralPath $isolatedArtifact -Algorithm SHA256).Hash
    if ($isolatedDigest -cne $env:TT_TEST_ARTIFACT_SHA256) { throw 'Isolated persisted artifact digest changed.' }

    & $module {
        param($counter)
        $script:TTAgentDestructiveApprovalResponseSourceForTesting = { $counter.Count++; '1' }.GetNewClosure()
    } $approvalCalls
    $prompt = 'Implement exactly one governed durable launch for the synthetic Scenario A snapshot reconciliation plan using the isolated semantic reconciliation tool. Expected output: return SCENARIO_A_LAUNCH_OK after one durable launch. Must not expand authority, select additional sources, perform publication, or wait for worker completion. Use the reviewed plan and return the exact launch result.'
    Mark 'invoke-started'
    $invocationOutput = & $module {
        param($promptText, $endpointUrl)
        Invoke-TechAgent -Prompt $promptText -Provider openai-compatible -Model scenario-a-deterministic-test-model -Endpoint $endpointUrl -Mode execute -OutputContract plain-text -SemanticKnowledgeRetrieval Disabled -AutoIngestBeforeRun Disabled -PromptHistoryItems 0 -ApiKeyEnvVar TT_AGENT_LLM_API_KEY -DisableApiKeyPrompt -DisableAutoRetryOnRecursion -Quiet
    } $prompt $env:TT_TEST_ENDPOINT_URL 2>&1 | Out-String
    Mark 'invoke-completed'
    & $module { $script:TTAgentDestructiveApprovalResponseSourceForTesting = $null }

    $statusPath = Join-Path $tt.LocalDataRoot 'Artifacts\agent-runtime\current-status.json'
    if (!(Test-Path -LiteralPath $statusPath -PathType Leaf)) { throw 'Recorder-produced runtime status is missing.' }
    $statusRaw = [IO.File]::ReadAllText($statusPath)
    $status = $statusRaw | ConvertFrom-Json
    $postflight = & $module {
        param($path, $processId, $runId)
        Get-TTAgentPostflightDecision -RuntimeStatusPath $path -ProcessId $processId -RunId $runId -TaskExecutionSucceeded $true -PostflightSucceeded $true -PostflightCompleted $true
    } $statusPath $status.ProcessId $status.RunId

    $jobRoot = Join-Path $localDataRoot 'Artifacts\semantic-indexing\Runtime\Maintenance\jobs'
    $jobStatuses = @()
    if (Test-Path -LiteralPath $jobRoot -PathType Container) {
        $jobStatuses = @(Get-ChildItem -LiteralPath $jobRoot -Filter '*.status.json' -File | ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Status = (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json) } })
    }
    $reconciliationJobs = @($jobStatuses | Where-Object { $_.Status.Operation -eq 'SemanticSnapshotReconciliation' })
    $returnedJobId = if ($reconciliationJobs.Count -eq 1) { [string]$reconciliationJobs[0].Status.JobId } else { '' }
    if ($reconciliationJobs.Count -eq 1) {
        $jobInputPath = Join-Path $jobRoot ($reconciliationJobs[0].Status.JobId + '.input.json')
        $jobInput = if (Test-Path -LiteralPath $jobInputPath -PathType Leaf) { Get-Content -LiteralPath $jobInputPath -Raw | ConvertFrom-Json } else { $null }
    } else { $jobInputPath = ''; $jobInput = $null }
    $jobStatusRaw = if ($reconciliationJobs.Count -eq 1) { [IO.File]::ReadAllText($reconciliationJobs[0].Path) } else { '' }
    $forbidden = @('approvedPlanJson', $env:TT_TEST_APPROVED_PLAN_JSON, 'toolArgs', '__destructive_approval_token', 'Authorization:', 'scenario-a-loopback-key', 'Synthetic Scenario A changed approved snapshot', 'stackTrace', 'vector')
    $forbiddenStatusMarkers = @($forbidden | Where-Object { -not [string]::IsNullOrEmpty([string]$_) -and $statusRaw.IndexOf([string]$_, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    $result = [ordered]@{
        Runtime = [string]$runtime; ExpectedRuntime = [string]$expectedRuntime; LocalAppData = [string]$env:LOCALAPPDATA
        LocalDataRoot = $localDataRoot; ProcessId = [int]$status.ProcessId; RuntimeStatusPath = $statusPath
        RuntimeStatus = $status; RuntimeStatusRaw = $statusRaw; InvocationOutput = [string]$invocationOutput
        ApprovalRequestCount = [int]$approvalCalls.Count; Postflight = $postflight
        JobStatuses = @($jobStatuses | ForEach-Object { $_.Status }); JobStatusPaths = @($jobStatuses | ForEach-Object { $_.Path })
        JobRoot = $jobRoot; JobInputPath = $jobInputPath; JobInput = $jobInput; JobStatusRaw = $jobStatusRaw
        WorkerProcessId = if ($reconciliationJobs.Count -eq 1) { $reconciliationJobs[0].Status.ProcessId } else { $null }
        WorkerProcessStartedAtUtc = if ($reconciliationJobs.Count -eq 1) { $reconciliationJobs[0].Status.ProcessStartedAtUtc } else { $null }
        ReturnedJobId = $returnedJobId; ForbiddenStatusMarkers = $forbiddenStatusMarkers
        IsolatedArtifact = $isolatedArtifact; IsolatedArtifactSha256 = $isolatedDigest
    }
    [IO.File]::WriteAllText($env:TT_TEST_EVIDENCE, ($result | ConvertTo-Json -Depth 12 -Compress), [Text.Encoding]::UTF8)
} catch {
    if ($module) { & $module { $script:TTAgentDestructiveApprovalResponseSourceForTesting = $null } 2>$null }
    $failure = $_.Exception.ToString()
    $runtimeStatus = if ($statusPath -and (Test-Path -LiteralPath $statusPath)) { [IO.File]::ReadAllText($statusPath) } else { '' }
    [IO.File]::WriteAllText($env:TT_TEST_EVIDENCE, (@{ Failure = $failure; RuntimeStatus = $runtimeStatus; InvocationOutput = $invocationOutput; Lifecycle = [IO.File]::ReadAllText($life) } | ConvertTo-Json -Depth 8 -Compress), [Text.Encoding]::UTF8)
    throw
}
'@
            $environment = @{
                TT_TEST_ROOT = $root
                TT_TEST_MANIFEST = $manifest
                TT_TEST_EVIDENCE = $evidencePath
                TT_TEST_ENDPOINT_URL = $endpoint.Url
                TT_TEST_FIXTURE_ARTIFACT = $script:scenarioAWorkerArtifactPath
                TT_TEST_PLAN_RUN_ID = $script:scenarioAPlanRunId
                TT_TEST_ARTIFACT_SHA256 = $script:scenarioAArtifactSha256
                TT_TEST_APPROVED_PLAN_JSON = $script:scenarioAApprovedPlanJson
                TT_TEST_WORKER_LOCAL_DATA_ROOT = $script:scenarioAWorkerLocalDataRoot
                TT_TEST_WORKER_ALLOWED_ROOTS = $script:scenarioAWorkerSourceRoot
                TT_TEST_WORKER_RETRIEVAL_CONFIG = $script:scenarioAWorkerRetrievalJson
                TT_TEST_WORKER_EMBEDDING_ENDPOINT = $script:scenarioAWorkerEndpoint.Url
            }
            $startInfo = New-TTE2EProcessStartInfo -Executable $pwsh -Arguments @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))) -LocalAppData (Join-Path $root 'bootstrap') -Environment $environment
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            if (!$process.Start()) { throw 'Fresh isolated governed-launch process did not start.' }
            $processTicks = $process.StartTime.ToUniversalTime().Ticks
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            $processResult = Wait-TTE2EProcessAndPipes -Process $process -StandardOutputTask $stdout -StandardErrorTask $stderr -TimeoutMilliseconds 120000 -EvidencePath $evidencePath -MaximumEvidenceBytes 4194304
            $evidence = $processResult.Evidence | ConvertFrom-Json
            if ($processResult.ExitCode -ne 0) { throw "Governed launch process failed: $($evidence.Failure); runtime=$($evidence.RuntimeStatus); lifecycle=$($evidence.Lifecycle)" }
            $endpoint.RequestCount | Should -Be 2
            @($endpoint.ResponseIndices) | Should -Be @(0, 1)
            @($endpoint.RequestOrder) | Should -Be @(1, 2)
            $endpoint.SequenceExhausted | Should -BeFalse
            $endpoint.LastPath | Should -BeExactly '/v1/chat/completions'
            $endpoint.LastMethod | Should -BeExactly 'POST'
            $endpoint.LastBody | Should -Match 'scenario-a-deterministic-test-model'
            $evidence.Runtime | Should -BeExactly $evidence.ExpectedRuntime
            $evidence.ExpectedRuntime | Should -Not -Match '[\\/]bin[\\/]Debug[\\/]'
            $evidence.LocalAppData.StartsWith(([IO.Path]::GetFullPath($root) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
            $evidence.LocalDataRoot.StartsWith(([IO.Path]::GetFullPath($root) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
            $evidence.IsolatedArtifactSha256 | Should -BeExactly $script:scenarioAArtifactSha256
            $evidence.ApprovalRequestCount | Should -Be 1
            $evidence.InvocationOutput.Trim() | Should -BeExactly 'SCENARIO_A_LAUNCH_OK'
            $evidence.ReturnedJobId | Should -Match '^[a-f0-9]{32}$'
            $evidence.JobStatuses | Should -HaveCount 1
            $evidence.JobStatuses[0].Operation | Should -BeExactly 'semanticSnapshotReconciliation'
            $evidence.JobStatuses[0].JobId | Should -BeExactly $evidence.ReturnedJobId
            $evidence.JobStatuses[0].PlanRunId | Should -BeExactly $script:scenarioAPlanRunId
            $evidence.JobStatuses[0].ArtifactSha256 | Should -BeExactly $script:scenarioAArtifactSha256
            $evidence.JobStatuses[0].ExplicitlyApproved | Should -BeTrue
            $evidence.JobStatuses[0].IsDryRun | Should -BeFalse
            $evidence.JobInput.PlanRunId | Should -BeExactly $script:scenarioAPlanRunId
            $evidence.JobInput.ArtifactSha256 | Should -BeExactly $script:scenarioAArtifactSha256
            $evidence.JobInput.ExplicitlyApproved | Should -BeTrue
            $evidence.JobInput.Operation | Should -BeExactly 'semanticSnapshotReconciliation'
            $evidence.JobStatusPaths | Should -HaveCount 1
            $evidence.JobStatusPaths[0].StartsWith(([IO.Path]::GetFullPath($root) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
            $evidence.JobInputPath.StartsWith(([IO.Path]::GetFullPath($root) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase) | Should -BeTrue

            $status = $evidence.RuntimeStatus
            $status.ProcessId | Should -Be $evidence.ProcessId
            $status.RunId | Should -Not -BeNullOrEmpty
            $status.LlmCallsStarted | Should -Be 2
            $status.LlmCallsCompleted | Should -Be 2
            $status.ToolCallsPrepared | Should -Be 1
            $status.ToolCallsStarted | Should -Be 1
            $status.ToolCallsCompleted | Should -Be 1
            $status.FinalResponseProduced | Should -BeTrue
            $status.TerminalState | Should -BeExactly 'Completed'
            $status.TerminalCode | Should -BeExactly 'COMPLETED'
            $status.DeadlineExceeded | Should -BeFalse
            $status.CancellationObserved | Should -BeFalse
            $evidence.Postflight.ArtifactCorrelated | Should -BeTrue
            $evidence.Postflight.KnownFailureDetected | Should -BeFalse
            $evidence.Postflight.TaskAchieved | Should -BeTrue
            $evidence.ForbiddenStatusMarkers | Should -BeNullOrEmpty
            $evidence.RuntimeStatusRaw | Should -Not -Match ([regex]::Escape($script:scenarioAApprovedPlanJson))
            $evidence.RuntimeStatusRaw | Should -Not -Match 'toolArgs|tool arguments|__destructive_approval_token|Authorization:|scenario-a-loopback-key|Synthetic Scenario A changed approved snapshot|stackTrace|vector'
            $jobStatusPath = Join-Path $evidence.JobRoot ($evidence.ReturnedJobId + '.status.json')
            foreach ($path in @($evidence.RuntimeStatusPath, $evidence.IsolatedArtifact, $evidence.JobRoot, $jobStatusPath, $evidence.JobInputPath)) {
                Assert-TTE2EPathUnderRoot -Path $path -Root $root
            }
            $script:scenarioALaunchEvidence = $evidence
            $script:scenarioALaunchJobId = $evidence.ReturnedJobId
        }
        finally {
            if ($endpoint) { Stop-TTE2ELoopbackEndpoint -Endpoint $endpoint }
            if ($process) {
                try { Stop-TTE2EOwnedProcess -Process $process -ProcessId $process.Id -StartTimeUtcTicks $processTicks -TimeoutMilliseconds 5000 }
                finally { $process.Dispose() }
            }
            # The detached worker is intentionally left running here. Its exact JobId is validated in the following test.
            Assert-TTE2EInventoryUnchanged -Before $liveBefore -After (Get-TTE2EInventory -Root $liveRoot)
        }
    }

    It 'waits for and validates the real detached Scenario A worker publication' {
        if (!$script:scenarioALaunchEvidence -or !$script:scenarioALaunchJobId -or !$script:scenarioAWorkerEndpoint) {
            throw 'Governed launch evidence or the production-persistent worker fixture is unavailable.'
        }
        $root = $script:scenarioAWorkerFixtureRoot
        $localDataRoot = $script:scenarioAWorkerLocalDataRoot
        $jobId = [string]$script:scenarioALaunchJobId
        $jobRoot = Join-Path $localDataRoot 'Artifacts\semantic-indexing\Runtime\Maintenance\jobs'
        $statusPath = Join-Path $jobRoot ($jobId + '.status.json')
        $resultPath = Join-Path $jobRoot ($jobId + '.result.json')
        $priorLocalData = [Environment]::GetEnvironmentVariable('TT_LocalDataRoot', 'Process')
        $priorLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
        $workerValidated = $false
        $retainWorkerFixture = $false
        $statusSnapshots = [Collections.Generic.List[object]]::new()
        $lastSnapshotFingerprint = $null
        $liveRoot = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'TechToolbox' } else { $null }
        $liveBefore = Get-TTE2EInventory -Root $liveRoot
        try {
            [Environment]::SetEnvironmentVariable('TT_LocalDataRoot', $localDataRoot, 'Process')
            [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $root 'local-app-data'), 'Process')
            Assert-TTE2EPathUnderRoot -Path $localDataRoot -Root $root
            Assert-TTE2EPathUnderRoot -Path $statusPath -Root $root
            Assert-TTE2EPathUnderRoot -Path $resultPath -Root $root
            $endpointUrl = [uri]$script:scenarioAWorkerEndpoint.Url
            $endpointUrl.Host | Should -BeExactly '127.0.0.1'
            $endpointUrl.Port | Should -Not -Be 11434

            $deadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
            $status = $null
            $workerIdentityEvidence = $null
            while ([DateTimeOffset]::UtcNow -lt $deadline) {
                if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
                    $candidate = [IO.File]::ReadAllText($statusPath) | ConvertFrom-Json
                    if ($candidate.JobId -cne $jobId) { throw 'Detached worker status JobId changed.' }
                    if ($candidate.PlanRunId -cne $script:scenarioAPlanRunId -or $candidate.ArtifactSha256 -cne $script:scenarioAArtifactSha256) {
                        throw 'Detached worker plan/artifact correlation changed.'
                    }
                    $bounded = [ordered]@{}
                    foreach ($name in @('CreatedAtUtc','StartedAtUtc','CompletedAtUtc','UpdatedAtUtc','State','Phase','FailureCode','FailureType','ProcessId','ProcessStartedAtUtc','ProcessExitCode','ProcessDiagnostic','TerminalOutcome','TerminalResultPersisted','TotalApprovedSources','ProcessedSources','Succeeded','SucceededSources','Failed','FailedSources','Conflicted','ConflictedSources','Publications','PublicationCount','LastProgressUtc')) {
                        $property = $candidate.PSObject.Properties[$name]
                        if ($property) {
                            $value = $property.Value
                            if ($name -eq 'ProcessDiagnostic' -and $null -ne $value) {
                                $value = [string]$value -replace '[\r\n\t]+', ' '
                                if ($value -match '(?i)stacktrace| at [\w`.+<>]+\(') { $value = $null }
                                elseif ($value.Length -gt 512) { $value = $value.Substring(0, 512) }
                            }
                            $bounded[$name] = $value
                        }
                    }
                    $bounded.JobId = $candidate.JobId
                    $bounded.PlanRunId = $candidate.PlanRunId
                    $bounded.ArtifactSha256 = $candidate.ArtifactSha256
                    $bounded.FailureSummaries = @($candidate.RecentFailureSummaries | Select-Object -First 16 | ForEach-Object {
                        [ordered]@{ SourceIdToken = $_.SourceIdToken; SourceSequence = $_.SourceSequence; AttemptId = $_.AttemptId; FailureCode = $_.FailureCode; AttemptPhase = $_.AttemptPhase; TimestampUtc = $_.TimestampUtc }
                    })
                    if ($candidate.ProcessId -is [int] -and $candidate.ProcessId -gt 0 -and $candidate.ProcessStartedAtUtc) {
                        $workerStartTicks = ([DateTimeOffset]::Parse([string]$candidate.ProcessStartedAtUtc)).UtcDateTime.Ticks
                        $ownedWorker = $null
                        try {
                            $ownedWorker = [Diagnostics.Process]::GetProcessById([int]$candidate.ProcessId)
                            $workerIdentityEvidence = [pscustomobject]@{ ProcessId = [int]$candidate.ProcessId; ProcessStartedAtUtc = [string]$candidate.ProcessStartedAtUtc; IdentityMatches = (Test-TTE2EOwnedProcessIdentity -Process $ownedWorker -ProcessId ([int]$candidate.ProcessId) -StartTimeUtcTicks $workerStartTicks) }
                        } catch [ArgumentException] { $workerIdentityEvidence = [pscustomobject]@{ ProcessId = [int]$candidate.ProcessId; ProcessStartedAtUtc = [string]$candidate.ProcessStartedAtUtc; IdentityMatches = $false } }
                        finally { if ($ownedWorker) { $ownedWorker.Dispose() } }
                    }
                    $fingerprint = $bounded | ConvertTo-Json -Compress -Depth 5
                    if ($fingerprint -cne $lastSnapshotFingerprint -and $statusSnapshots.Count -lt 512) {
                        $statusSnapshots.Add([pscustomobject]@{ ObservedAtUtc = [DateTimeOffset]::UtcNow.ToString('O'); StatusFileLastWriteTimeUtc = (Get-Item -LiteralPath $statusPath).LastWriteTimeUtc.ToString('O'); WorkerIdentity = $workerIdentityEvidence; Status = $bounded })
                        $lastSnapshotFingerprint = $fingerprint
                    }
                    if ($candidate.State -in @('succeeded','failed','canceled','abandoned')) { $status = $candidate; break }
                }
                Start-Sleep -Milliseconds 100
            }
            if (!$status) { throw "Bounded wait expired for test-owned reconciliation job $jobId." }

            $allStatusFiles = @(Get-ChildItem -LiteralPath $jobRoot -Filter '*.status.json' -File -ErrorAction Stop)
            $allStatusFiles | Should -HaveCount 1
            if ($status.State -cne 'succeeded') {
                $retainWorkerFixture = $true
                $script:scenarioAWorkerFailureRetain = $true
                $failureSummaries = @($status.RecentFailureSummaries | ForEach-Object { $_.FailureCode })
                $resultMetadata = $null
                if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
                    $rawResult = [IO.File]::ReadAllText($resultPath) | ConvertFrom-Json
                    $resultMetadata = [ordered]@{}
                    foreach ($name in @('JobId','PlanRunId','ArtifactSha256','TerminalOutcome','TerminalResultPersisted','ProcessedPlans','Succeeded','Failed','Conflicted','Publications','PublicationCount')) {
                        $property = $rawResult.PSObject.Properties[$name]
                        if ($property) { $resultMetadata[$name] = $property.Value }
                    }
                }
                $inputMetadata = [ordered]@{}
                foreach ($name in @('JobId','PlanRunId','ArtifactSha256','Operation','ExplicitlyApproved')) {
                    $property = $script:scenarioALaunchEvidence.JobInput.PSObject.Properties[$name]
                    if ($property) { $inputMetadata[$name] = $property.Value }
                }
                $retrievalFailureObservations = [Collections.Generic.List[object]]::new()
                foreach ($snapshot in $statusSnapshots) {
                    foreach ($failure in $snapshot.Status.FailureSummaries) {
                        if ($failure.FailureCode -match '(?i)RETRIEVAL|INVALIDOPERATION') {
                            $retrievalFailureObservations.Add([ordered]@{
                                FailureCode = $failure.FailureCode; SourceSequence = $failure.SourceSequence; AttemptId = $failure.AttemptId
                                AttemptPhase = $failure.AttemptPhase; TimestampUtc = $failure.TimestampUtc
                                ObservedAtUtc = $snapshot.ObservedAtUtc; StatusFileLastWriteTimeUtc = $snapshot.StatusFileLastWriteTimeUtc
                                Writer = 'SemanticIndexMaintenanceRunner.UpdateSemanticRebuildStatus'
                            })
                        }
                    }
                }
                $baselineRequestNumbers = @($script:scenarioAWorkerInitialRequestEvidence | ForEach-Object { ([string]$_ | ConvertFrom-Json).requestNumber })
                $baselineRequestNumber = if ($baselineRequestNumbers.Count) { [int]($baselineRequestNumbers | Measure-Object -Maximum).Maximum } else { 0 }
                $allEmbeddingRequests = @($script:scenarioAWorkerEndpoint.RequestEvidence | ForEach-Object { [string]$_ | ConvertFrom-Json })
                $diagnostic = [ordered]@{
                    JobId = $jobId; PlanRunId = $script:scenarioAPlanRunId; ArtifactSha256 = $script:scenarioAArtifactSha256
                    InputPath = $script:scenarioALaunchEvidence.JobInputPath; InputMetadata = $inputMetadata
                    StatusPath = $statusPath; ResultPath = $resultPath; ResultMetadata = $resultMetadata
                    WorkerProcessId = $status.ProcessId; WorkerProcessStartedAtUtc = $status.ProcessStartedAtUtc
                    WorkerIdentity = $workerIdentityEvidence
                    StatusSnapshots = @($statusSnapshots); TerminalStatus = @($statusSnapshots | Select-Object -Last 1).Status
                    RetrievalFailureObservations = @($retrievalFailureObservations)
                    EmbeddingRequestEvidence = @($allEmbeddingRequests)
                    PreLaunchEmbeddingRequestEvidence = @($allEmbeddingRequests | Where-Object { $_.requestNumber -le $baselineRequestNumber })
                    PostLaunchEmbeddingRequestEvidence = @($allEmbeddingRequests | Where-Object { $_.requestNumber -gt $baselineRequestNumber })
                    PreLaunchEmbeddingRequestCount = $baselineRequestNumber
                    PostLaunchEmbeddingRequestCount = @($allEmbeddingRequests | Where-Object { $_.requestNumber -gt $baselineRequestNumber }).Count
                    ParentLaunchFailureWriter = 'SemanticIndexMaintenanceRunner.Launch catch block: RUNNER_START_FAILED / ProcessStartException'
                    ParentLaunchFailureWriterEvidenceTime = @($statusSnapshots | Where-Object { $_.Status.FailureCode -eq 'RUNNER_START_FAILED' } | Select-Object -First 1).StatusFileLastWriteTimeUtc
                }
                $diagnosticPath = Join-Path $root 'scenario-a-worker-diagnostics.json'
                [IO.File]::WriteAllText($diagnosticPath, ($diagnostic | ConvertTo-Json -Depth 12 -Compress), [Text.Encoding]::UTF8)
                Write-Host "Retained Scenario A diagnostic fixture: $root"
                throw "Detached worker terminal failure: state=$($status.State); code=$($status.FailureCode); type=$($status.FailureType); diagnostic=$($status.ProcessDiagnostic); terminal=$($status.TerminalOutcome); failureSummaries=$($failureSummaries -join ','); diagnostics=$diagnosticPath"
            }
            $status.State | Should -BeExactly 'succeeded'
            $status.Operation | Should -BeExactly 'SemanticSnapshotReconciliation'
            $status.JobId | Should -BeExactly $jobId
            $status.PlanRunId | Should -BeExactly $script:scenarioAPlanRunId
            $status.ArtifactSha256 | Should -BeExactly $script:scenarioAArtifactSha256
            $status.TotalApprovedSources | Should -Be 1
            $status.ProcessedSources | Should -Be 1
            $status.SucceededSources | Should -Be 1
            $status.FailedSources | Should -Be 0
            $status.ConflictedSources | Should -Be 0
            $status.TotalDenseGenerationsCreated | Should -Be 1
            $status.TotalLexicalGenerationsCreated | Should -Be 1
            $status.CompletedAtUtc | Should -Not -BeNullOrEmpty
            (Test-Path -LiteralPath $resultPath -PathType Leaf) | Should -BeTrue
            $resultRaw = [IO.File]::ReadAllText($resultPath)
            $result = $resultRaw | ConvertFrom-Json
            $result.PlanRunId | Should -BeExactly $script:scenarioAPlanRunId
            $result.ArtifactSha256 | Should -BeExactly $script:scenarioAArtifactSha256
            $result.TargetEmbeddingFingerprint | Should -BeExactly $script:scenarioAWorkerEmbeddingFingerprint
            $result.TotalApprovedPlans | Should -Be 1
            $result.ProcessedPlans | Should -Be 1
            $result.Succeeded | Should -Be 1
            $result.Failed | Should -Be 0
            $result.Conflicted | Should -Be 0
            $result.DenseGenerationsCreated | Should -Be 1
            $result.LexicalGenerationsCreated | Should -Be 1
            $result.PublicationCount | Should -Be 1
            $result.CompletedAllApprovedPlans | Should -BeTrue
            $result.TerminalOutcome | Should -BeExactly 'completed'

            $script:scenarioAWorkerEndpoint.RequestCount | Should -BeGreaterThan $script:scenarioAWorkerInitialEndpointRequests
            $script:scenarioAWorkerEndpoint.TagCount | Should -BeGreaterThan $script:scenarioAWorkerInitialTags
            $script:scenarioAWorkerEndpoint.EmbedCount | Should -BeGreaterThan $script:scenarioAWorkerInitialEmbeds

            $lifecycle = [TechToolbox.Agent.Retrieval.ProductionSourceIndexLifecycleConfiguration]::CreateDefault()
            foreach ($path in @($lifecycle.ManifestRoot, $lifecycle.DenseRoot, $lifecycle.LexicalRoot)) { Assert-TTE2EPathUnderRoot -Path $path -Root $localDataRoot }
            $manifests = $lifecycle.CreateManifestStore()
            $current = $manifests.ReadCurrentAsync($script:scenarioAWorkerPredecessor.Source.SourceId).GetAwaiter().GetResult()
            $current.State.ToString() | Should -BeExactly 'Committed'
            $current.Revision | Should -Be ($script:scenarioAWorkerManifestRevision + 1)
            $current.SnapshotIdentity.ContentHash | Should -BeExactly $script:scenarioAWorkerApprovedSnapshot.Identity.ContentHash
            $current.DenseBuild.GenerationId | Should -Not -BeExactly $script:scenarioAWorkerDenseGenerationId
            $current.LexicalBuild.GenerationId | Should -Not -BeExactly $script:scenarioAWorkerLexicalGenerationId
            $current.DenseBuild.SpecificationFingerprint | Should -BeExactly $script:scenarioAWorkerEmbeddingFingerprint
            $targetDenseBuild = [TechToolbox.Agent.Retrieval.DenseSourceIndexBuildSpecification]::new($current.DenseBuild,
                $script:scenarioAWorkerArtifact.RequestedEmbeddingSpecification.ModelId,
                $script:scenarioAWorkerArtifact.RequestedEmbeddingSpecification.VectorDimension)
            $targetLexicalBuild = [TechToolbox.Agent.Retrieval.LexicalSourceIndexBuildSpecification]::new($current.LexicalBuild,
                [TechToolbox.Agent.Retrieval.VersionedLexicalAnalyzer]::CurrentVersion)
            $denseWriter = $lifecycle.CreateDenseWriter()
            $lexicalWriter = $lifecycle.CreateLexicalWriter()
            $denseVerify = $denseWriter.VerifyGenerationAsync($script:scenarioAWorkerApprovedSnapshot,
                $current.DenseBuild.GenerationId, $targetDenseBuild).GetAwaiter().GetResult()
            $lexicalVerify = $lexicalWriter.VerifyGenerationAsync($script:scenarioAWorkerApprovedSnapshot,
                $current.LexicalBuild.GenerationId, $targetLexicalBuild).GetAwaiter().GetResult()
            $denseVerify.IsValid | Should -BeTrue
            $lexicalVerify.IsValid | Should -BeTrue

            $predecessorDenseBuild = [TechToolbox.Agent.Retrieval.DenseSourceIndexBuildSpecification]::new(
                $script:scenarioAWorkerPredecessorManifest.DenseBuild,
                $script:scenarioAWorkerPredecessorManifest.DenseBuild.SpecificationFingerprint,
                $script:scenarioAWorkerPredecessorManifest.DenseBuild.VectorDimension)
            $predecessorLexicalBuild = [TechToolbox.Agent.Retrieval.LexicalSourceIndexBuildSpecification]::new(
                $script:scenarioAWorkerPredecessorManifest.LexicalBuild,
                [TechToolbox.Agent.Retrieval.VersionedLexicalAnalyzer]::CurrentVersion)
            $oldDenseVerify = $denseWriter.VerifyGenerationAsync($script:scenarioAWorkerPredecessor,
                $script:scenarioAWorkerDenseGenerationId, $predecessorDenseBuild).GetAwaiter().GetResult()
            $oldLexicalVerify = $lexicalWriter.VerifyGenerationAsync($script:scenarioAWorkerPredecessor,
                $script:scenarioAWorkerLexicalGenerationId, $predecessorLexicalBuild).GetAwaiter().GetResult()
            $oldDenseVerify.IsValid | Should -BeTrue
            $oldLexicalVerify.IsValid | Should -BeTrue
            (Test-Path -LiteralPath (Join-Path $lifecycle.DenseRoot $script:scenarioAWorkerDenseGenerationId) -PathType Container) | Should -BeTrue
            (Test-Path -LiteralPath (Join-Path $lifecycle.LexicalRoot $script:scenarioAWorkerLexicalGenerationId) -PathType Container) | Should -BeTrue
            $current.Revision | Should -Not -Be $script:scenarioAWorkerManifestRevision

            $attemptId = $script:scenarioAWorkerArtifact.Outcomes[0].ApprovedPlan.AttemptId
            $attempt = $manifests.TryReadAttemptAsync($script:scenarioAWorkerPredecessor.Source.SourceId, $attemptId).GetAwaiter().GetResult()
            $attempt.Phase.ToString() | Should -BeExactly 'Completed'
            $attempt.SnapshotIdentity.ContentHash | Should -BeExactly $script:scenarioAWorkerApprovedSnapshot.Identity.ContentHash
            $denseNames = @((Get-ChildItem -LiteralPath $lifecycle.DenseRoot -Directory -ErrorAction Stop).Name)
            $lexicalNames = @((Get-ChildItem -LiteralPath $lifecycle.LexicalRoot -Directory -ErrorAction Stop).Name)
            $denseNames | Should -Contain $script:scenarioAWorkerDenseGenerationId
            $denseNames | Should -Contain $current.DenseBuild.GenerationId
            $lexicalNames | Should -Contain $script:scenarioAWorkerLexicalGenerationId
            $lexicalNames | Should -Contain $current.LexicalBuild.GenerationId
            $script:scenarioAWorkerEndpoint.Url | Should -Match '^http://127\.0\.0\.1:[0-9]+$'
            $script:scenarioAWorkerEndpoint.Url | Should -Not -Match '11434'

            foreach ($forbidden in @('scenario-a-loopback-key','approvedPlanJson','__destructive_approval_token','Authorization:',
                    'Synthetic changed approved snapshot for the production-persistent worker fixture','"vectors"','"embedding"','stackTrace')) {
                $resultRaw | Should -Not -Match ([regex]::Escape($forbidden))
                [IO.File]::ReadAllText($statusPath) | Should -Not -Match ([regex]::Escape($forbidden))
                $script:scenarioALaunchEvidence.RuntimeStatusRaw | Should -Not -Match ([regex]::Escape($forbidden))
            }
            foreach ($path in @($statusPath, $resultPath, $script:scenarioALaunchEvidence.RuntimeStatusPath,
                    $script:scenarioALaunchEvidence.IsolatedArtifact, $script:scenarioALaunchEvidence.JobInputPath)) {
                Assert-TTE2EPathUnderRoot -Path $path -Root $root
            }
            $workerValidated = $true
            $script:scenarioAWorkerTerminalStatus = $status
            $script:scenarioAWorkerStatusSnapshots = @($statusSnapshots)
            $script:scenarioAWorkerTerminalResult = $result
        }
        finally {
            [Environment]::SetEnvironmentVariable('TT_LocalDataRoot', $priorLocalData, 'Process')
            [Environment]::SetEnvironmentVariable('LOCALAPPDATA', $priorLocalAppData, 'Process')
            if ($status -and $status.ProcessId -is [int] -and $status.ProcessId -gt 0 -and $status.ProcessStartedAtUtc) {
                try {
                    $worker = [Diagnostics.Process]::GetProcessById([int]$status.ProcessId)
                    $ticks = ([DateTimeOffset]::Parse([string]$status.ProcessStartedAtUtc)).UtcDateTime.Ticks
                    if (Test-TTE2EOwnedProcessIdentity -Process $worker -ProcessId ([int]$status.ProcessId) -StartTimeUtcTicks $ticks) {
                        Stop-TTE2EOwnedProcess -Process $worker -ProcessId ([int]$status.ProcessId) -StartTimeUtcTicks $ticks -TimeoutMilliseconds 5000
                    }
                    $worker.Dispose()
                } catch [ArgumentException] { }
            }
            if ($script:scenarioAWorkerEndpoint) { $script:scenarioAWorkerEndpoint.Dispose(); $script:scenarioAWorkerEndpoint = $null }
            if ($workerValidated -and !$retainWorkerFixture -and $root -and (Test-Path -LiteralPath $root)) {
                Remove-TTE2EOwnedRoot -Path $root -ExpectedPrefix 'tt-reconciliation-worker-fixture-'
                $script:scenarioAWorkerFixtureRoot = $null
            }
            Assert-TTE2EInventoryUnchanged -Before $liveBefore -After (Get-TTE2EInventory -Root $liveRoot)
        }
    }

    It 'fails closed on a request beyond the deterministic response sequence' {
        function Invoke-TTE2EReconciliationExhaustionRequest {
            param([Parameter(Mandatory)][string]$Url)
            $client = [Net.Http.HttpClient]::new()
            try {
                $response = $client.PostAsync($Url + '/v1/chat/completions', [Net.Http.StringContent]::new('{"request":true}', [Text.Encoding]::UTF8, 'application/json')).GetAwaiter().GetResult()
                $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $body }
            }
            finally { $client.Dispose() }
        }
        $endpoint = New-TTE2ELoopbackEndpoint -ResponseBodies @('sequence-only-response')
        try {
            (Invoke-TTE2EReconciliationExhaustionRequest -Url $endpoint.Url).Body | Should -BeExactly 'sequence-only-response'
            $exhausted = Invoke-TTE2EReconciliationExhaustionRequest -Url $endpoint.Url
            $exhausted.StatusCode | Should -Be 503
            $exhausted.Body | Should -BeNullOrEmpty
            $endpoint.RequestCount | Should -Be 2
            @($endpoint.ResponseIndices) | Should -Be @(0, -1)
            @($endpoint.RequestOrder) | Should -Be @(1, 2)
            $endpoint.SequenceExhausted | Should -BeTrue
        }
        finally { Stop-TTE2ELoopbackEndpoint -Endpoint $endpoint }
    }

    AfterAll {
        if ($script:scenarioAWorkerFixtureRoot -and (Test-Path -LiteralPath $script:scenarioAWorkerFixtureRoot)) {
            if ($script:scenarioAWorkerEndpoint) { $script:scenarioAWorkerEndpoint.Dispose(); $script:scenarioAWorkerEndpoint = $null }
            if ($script:scenarioAWorkerFailureRetain) { Write-Host "Retained Scenario A diagnostic fixture: $script:scenarioAWorkerFixtureRoot" }
            else { Remove-TTE2EOwnedRoot -Path $script:scenarioAWorkerFixtureRoot -ExpectedPrefix 'tt-reconciliation-worker-fixture-' }
        }
        if ($script:scenarioAFixtureRoot -and $script:scenarioAFixtureRoot -cne $script:scenarioAWorkerFixtureRoot -and (Test-Path -LiteralPath $script:scenarioAFixtureRoot)) {
            Remove-TTE2EOwnedRoot -Path $script:scenarioAFixtureRoot -ExpectedPrefix 'tt-reconciliation-e2e-'
        }
        $script:scenarioAFixtureRoot = $null
        $script:scenarioAWorkerFixtureRoot = $null
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD8kg+QVK8qN2OA
# 1ibYonb4f9MS6oHJRFEpEAcJNA/zhaCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAV
# HdrFu/WQE3wCPMTAPVusFVARDXy5/0wlbVX9+beWJTANBgkqhkiG9w0BAQEFAASC
# AYBlIsoywhASR/shbVMoTvkUiQKYUzOZMb7mJL6psf0m51oR/zWkbLgz7ejddEZL
# vQe3Ve+9xM/TfLCVQ2eVXoIgJ7V26sYjdrFICwARa1RoBEcZUQ+QEnYNQTlnyKaP
# 1eqWxIPz2e47TDqZNd+vwdsbhfs+icorly50ijpN25y5uf6/KD0oaWkyTWdQxJiJ
# ULOTD5q6xLFbO3OZSVCgLsJq1/pTsEzh/UQlT+gnFo6ggK7oi0mdl7cSAQneEH81
# uL/vQDhFPFMWksHLO0909H+ypU6mVG1e7W17wXYLDsWopsOcdxXh//DtSQgiY3ov
# ZO2vy5YxWBk9Luxxt70kM7y+YppEY9j0jO2blXpAHZ93tndDiP7G1PnQ4pwjxezM
# WujDzqgWQNBBvUB70G2Nb+xZWtaUI4dsG7xLX2yf70PdkgGpi0fEgrZ71okcTzV+
# L/dGG7KSe4sg0PhQY1KfSQT+sJQxOOyMUwabB2vcOwvVndhrha6xgb7xrHRTAz5h
# 5nShggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTA5MDMxNjQ1WjAvBgkqhkiG
# 9w0BCQQxIgQg/DFMghxTKt4xVtqX7Nx3gVzYKKaoNvnKjExlNgIQ5TcwDQYJKoZI
# hvcNAQEBBQAEggIAYeVW56dJmW1tQIuTx3Xp+2NiUes+vMZhQNuvv0ZU5Q0mw0k4
# +4/kzvdF2zXxWs0tAkRJqm34EkLD1ZDK05I65Mee/fRhM7Y1ZlDcljfjr8WNwJJr
# WoKrs++ulb4IJcyDlcb7SO3/qf7ZlJA1VXblS1wYb0utdlSvUEYXR1kABhfTqClt
# MQf5/QARPbPvODW9m4ws2wt9mBYawDZj0fIv3b67GvPDEfg3f26EYhLH96us/Yr/
# jHray44DVXPGuznApG4xtvjVHOeu53aM/889GwOlJP+4cSdhIjCZq2Kkka+LmhAh
# 9m4lX/9+WARB7JT7X5covDZro2jcPPGRw8W5ZtPN/fGUPSC2BRWZgIsU7IAVjmKT
# uOnS3ZtRGaC9OAPs2UChRI2ls/N/EInU40Yyj5qRL+YE2yTUc3ZLRaih9PVsRmrt
# 1DYYAEIWGyWybR3L0VnvrtpWkIz41RiEAxM3gPa4JUC7mGsIYIapRIUZLH7xsGKQ
# bu4nOc52GWWcZQ0H6OcaAJvtUYBW+AbqsdF361ktfxogRP3D2XqxGM80Eff5exXj
# TYlhoo+Y3zrt6WC3l+0EXkYzOzITGBdcJZc1aoMHV8W0Zzo+/wTMdtA/2KtvLfN8
# bjQXp6+jaCS+/Ku2gSb6X+cPX6SKqBD6ZulzxE8QcEPcoO8amit4j9Lmb0E=
# SIG # End signature block
