#!/bin/bash -eux

AUTHOR="Maximilian Blochberger"
AUTHOR_URL="https://github.com/blochberger"
GITHUB_URL="https://github.com/blochberger/Tafelsalz"
MODULE="Tafelsalz"
README="README.md"
VERSION=$(git describe --always)
LAST_COMMIT=$(git log -1 --format='%H')
GITHUB_FILE_PREFIX="${GITHUB_URL}/blob/${LAST_COMMIT}"
OUTPUT_DIR="gh-pages"

JAZZY="jazzy"
JAZZY_THEME="fullwidth"

COMMIT=false
RUN_TESTS=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
	key="$1"

	case $key in
		--commit)
			COMMIT=true
			shift
			;;
		--test)
			RUN_TESTS=true
			shift
			;;
		-h|--help)
			echo "Usage: [--test] [--commit] [-h|--help]" >&2
			exit 0
			;;
		*)
			echo "Usage: [--test] [--commit] [-h|--help]" >&2
			echo "Unknown option: ${key}" >&2
			exit 1
			;;
	esac
done

# Generate documentation
for SDK in macos iphone; do
	for MIN_ACL in public private internal; do
		OUTPUT="${OUTPUT_DIR}/${SDK}/${MIN_ACL}"

		${JAZZY}\
			--clean\
			--use-safe-filenames\
			--theme="${JAZZY_THEME}"\
			--author="${AUTHOR}"\
			--author_url="${AUTHOR_URL}"\
			--github_url="${GITHUB_URL}"\
			--github-file-prefix="${GITHUB_FILE_PREFIX}"\
			--readme="${README}"\
			--module="${MODULE}"\
			--module-version="${VERSION}"\
			--sdk="${SDK}"\
			--min-acl="${MIN_ACL}"\
			--output="${OUTPUT}"
	done # MIN_ACL
done # SDK

# Execute unit tests and create test coverage badge
if [ ${RUN_TESTS} = true ]; then
	xcodebuild\
		-quiet\
		-sdk macosx\
		-project "${MODULE}.xcodeproj"\
		-scheme "${MODULE}_macOS"\
		-enableCodeCoverage YES\
		-derivedDataPath "build"\
		clean\
		test

	xcrun xccov view --json build/Logs/Test/*.xccovreport > build/coverage.json

	COVERAGE=$(
		python3 "extract_coverage.py" "${MODULE}.framework" < build/coverage.json
	)

	# See https://github.com/realm/jazzy/blob/a02fe0a86e02e5e0d67e96a05d5040478a8a36a3/lib/jazzy/doc_builder.rb#L239-L253
	if [[ ${COVERAGE} -lt 10 ]]; then
		COLOR='red'
	elif [[ ${COVERAGE} -lt 30 ]]; then
		COLOR='orange'
	elif [[ ${COVERAGE} -lt 60 ]]; then
		COLOR='yellow'
	elif [[ ${COVERAGE} -lt 85 ]]; then
		COLOR='yellowgreen'
	elif [[ ${COVERAGE} -lt 90 ]]; then
		COLOR='green'
	else
		COLOR='brightgreen'
	fi

	curl\
		--progress-bar\
		--output "${OUTPUT_DIR}/macos/coverage.svg"\
		"https://img.shields.io/badge/coverage-${COVERAGE}%25-${COLOR}.svg"

	xcov\
		--html_report\
		--scheme "${MODULE}_macOS"\
		--include_targets "${MODULE}.framework"\
		--output_directory "${OUTPUT_DIR}/macos/coverage"
fi

# Commit results
if [ ${COMMIT} = true ]; then
	(
		cd "${OUTPUT_DIR}"
		git add iphone macos
		git commit -m "Update documentation to ${VERSION}"
	)
fi

# Cleanup
rm -rf build
