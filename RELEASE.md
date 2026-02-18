## Releasing

Releases are automated via GitHub Actions using [GoReleaser](https://goreleaser.com/).

### How It Works

1. **Trigger**: Push a version tag (e.g., `v1.0.0`) to trigger the release workflow
2. **Tests**: The CI runs all unit tests before building
3. **Build**: GoReleaser builds self-contained binaries for multiple platforms
4. **Publish**: Binaries are uploaded to GitHub Releases as a draft

### Supported Platforms

| OS      | Architecture |
|---------|--------------|
| macOS   | arm64, amd64 |
| Linux   | arm64, amd64 |
| Windows | amd64        |

### Creating a Release

```bash
# 1. Ensure you're on main with latest changes
git checkout main
git pull origin main

# 2. Create and push a version tag
git tag v1.0.0
git push origin v1.0.0
```

The release workflow will:
- Run unit tests
- Build binaries for all platforms with version/commit info embedded
- Create a draft GitHub Release with the binaries and checksums

### Testing Releases Locally

You can test the release process locally without publishing:

```bash
# Requires goreleaser installed: brew install goreleaser
make release-local
```

This creates binaries in `dist/` for all platforms.

### Version Information

The binary embeds version and commit information at build time:

```go
import "github.com/DataDog/datadog-saist/internal/model"

fmt.Println(model.Version)   // e.g., "v1.0.0" or "dev"
fmt.Println(model.SCMCommit) // e.g., "abc123..." or "unknown"
```

## Development

### Local development with dd-source via shim

You can point dd-source to your local copy of this repo to speed up development.

```shell
make local-dev
```

From there, in your IDE working on dd-source, run a Bazel sync.