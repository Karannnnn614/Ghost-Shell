pipeline {
    agent any
    options { disableConcurrentBuilds() }

    environment {
        GOROOT   = '/usr/local/go'
        PATH     = "${GOROOT}/bin:${env.PATH}"
        GOPATH   = "${env.WORKSPACE}/.gopath"
        GOCACHE  = "${env.WORKSPACE}/.gocache"
        CGO_ENABLED = '0'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Release Version') {
            steps {
                script {
                    env.RELEASE_VERSION = sh(script: '''
                        set -e
                        tag=$(git tag --points-at HEAD --list 'v*' |
                            grep -E '^v[0-9]+[.][0-9]+[.][0-9]+$' |
                            sort -V | tail -1)
                        if [ -n "$tag" ]; then
                            printf '%s\n' "${tag#v}"
                            exit 0
                        fi

                        latest=$(git tag --list 'v*' |
                            grep -E '^v[0-9]+[.][0-9]+[.][0-9]+$' |
                            sort -V | tail -1)
                        latest=${latest:-v0.0.0}
                        version=${latest#v}
                        major=${version%%.*}
                        remainder=${version#*.}
                        minor=${remainder%%.*}
                        patch=${remainder##*.}
                        printf '%s.%s.%s\n' "$major" "$minor" "$((patch + 1))"
                    ''', returnStdout: true).trim()
                    echo "Release version: v${env.RELEASE_VERSION}"

                    withCredentials([string(credentialsId: 'github-release-token', variable: 'GH_TOKEN')]) {
                        sh '''
                            set -e
                            version="${RELEASE_VERSION}"

                            sed -i -E "s/^VERSION [?]= .*/VERSION ?= ${version}/" Makefile
                            sed -i -E "s/ghostshell [0-9]+[.][0-9]+[.][0-9]+/ghostshell ${version}/" man/ghostshell.1
                            sed -i -E \
                                -e "s#releases/download/v[0-9]+[.][0-9]+[.][0-9]+#releases/download/v${version}#g" \
                                -e "s#ghostshell_[0-9]+[.][0-9]+[.][0-9]+#ghostshell_${version}#g" \
                                -e "s#ghostshell-[0-9]+[.][0-9]+[.][0-9]+#ghostshell-${version}#g" \
                                README.md

                            if git diff --quiet -- Makefile man/ghostshell.1 README.md; then
                                echo "Versioned source files already match v${version}"
                                exit 0
                            fi

                            git config user.name "ghostshell Jenkins"
                            git config user.email "noreply@ghostshell.invalid"
                            git add Makefile man/ghostshell.1 README.md
                            git commit -m "chore: set release version v${version}"

                            set +x
                            auth=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\\n')
                            git -c http.extraHeader="Authorization: Basic ${auth}" push origin HEAD:main
                        '''
                    }
                }
            }
        }

        stage('Format') {
            steps {
                sh '''
                    unformatted=$(find . -name "*.go" \
                        -not -path "./.gopath/*" \
                        -not -path "./.gocache/*" \
                        -not -path "./vendor/*" \
                        | xargs gofmt -l)
                    if [ -n "$unformatted" ]; then
                        echo "Not gofmt-clean:"
                        echo "$unformatted"
                        exit 1
                    fi
                '''
            }
        }

        stage('Vet') {
            steps {
                sh 'go vet ./...'
            }
        }

        stage('Static Analysis') {
            steps {
                sh '''
                    set -e
                    # Install pinned static-analysis tools into GOPATH/bin if absent.
                    SC="${GOPATH}/bin/staticcheck"
                    if [ ! -x "$SC" ]; then
                        GOBIN="${GOPATH}/bin" go install honnef.co/go/tools/cmd/staticcheck@latest
                    fi
                    "$SC" ./...

                    GCL="${GOPATH}/bin/golangci-lint"
                    if [ ! -x "$GCL" ]; then
                        GOBIN="${GOPATH}/bin" go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
                    fi
                    "$GCL" run ./...
                '''
            }
        }

        stage('Test') {
            steps {
                sh 'go test ./... -v -count=1 2>&1 | tee test-results.txt'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'test-results.txt', allowEmptyArchive: true
                }
            }
        }

        stage('Build') {
            steps {
                sh '''
                    mkdir -p build bin
                    VERSION="${RELEASE_VERSION}"
                    go build -ldflags "-X main.Version=${VERSION}" -o build/ghostshell  ./cmd/ghostshell/
                    go build -o build/ghostshell-daemon ./cmd/ghostshell-daemon/
                    cp build/ghostshell  bin/ghostshell
                    cp build/ghostshell-daemon bin/ghostshell-daemon
                '''
            }
            post {
                success {
                    archiveArtifacts artifacts: 'build/ghostshell,build/ghostshell-daemon', fingerprint: true
                }
            }
        }

        stage('Package') {
            steps {
                sh '''
                    mkdir -p release
                    rm -f release/*.rpm release/*.deb release/ghostshell-*-linux-amd64 release/SHA256SUMS
                    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
                    NFPM="${GOPATH}/bin/nfpm"
                    VERSION="${RELEASE_VERSION}"
                    GHOSTSHELL_VERSION="$VERSION" "$NFPM" pkg --config nfpm.yaml --packager rpm --target release/
                    GHOSTSHELL_VERSION="$VERSION" "$NFPM" pkg --config nfpm.yaml --packager deb --target release/
                    cp build/ghostshell "release/ghostshell-${VERSION}-linux-amd64"
                    (cd release && sha256sum * > SHA256SUMS)
                '''
            }
            post {
                success {
                    archiveArtifacts artifacts: 'release/*', allowEmptyArchive: true, fingerprint: true
                }
            }
        }

        stage('Publish GitHub Release') {
            when {
                expression { env.GIT_BRANCH == 'origin/main' || env.BRANCH_NAME == 'main' }
            }
            steps {
                withCredentials([string(credentialsId: 'github-release-token', variable: 'GH_TOKEN')]) {
                    sh '''
                        set -e

                        GH="${GOPATH}/bin/gh"
                        if [ ! -x "$GH" ]; then
                            GOBIN="${GOPATH}/bin" go install github.com/cli/cli/v2/cmd/gh@v2.87.3
                        fi

                        version="${RELEASE_VERSION}"
                        target=$(git rev-parse HEAD)
                        repo="karan/ghostshell-tracker"
                        if "$GH" release view "v${version}" --repo "$repo" >/dev/null 2>&1; then
                            echo "Release v${version} already exists"
                        else
                            "$GH" release create "v${version}" --repo "$repo" \
                                --target "$target" --title "v${version}" --notes "ghostshell ${version}"
                        fi
                        "$GH" release upload "v${version}" release/*.rpm release/*.deb \
                            "release/ghostshell-${version}-linux-amd64" release/SHA256SUMS \
                            --repo "$repo" --clobber
                    '''
                }
            }
        }
    }

    post {
        failure {
            echo "Pipeline failed — check logs above"
        }
        success {
            echo "Pipeline passed ✓"
        }
    }
}
