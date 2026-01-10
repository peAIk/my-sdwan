#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Check if a commit message is provided
if [ -z "$1" ]; then
  echo "Error: Commit message is required."
  echo "Usage: ./git_update.sh \"Your commit message\""
  exit 1
fi

# Get the commit message from the first argument
COMMIT_MESSAGE="$1"

# Get the current branch name
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

echo "Adding all changes..."
git add .

echo "Committing with message: '$COMMIT_MESSAGE'"
git commit -m "$COMMIT_MESSAGE"

echo "Pushing to origin branch '$CURRENT_BRANCH'..."
git push origin "$CURRENT_BRANCH"

echo "Git update complete."

