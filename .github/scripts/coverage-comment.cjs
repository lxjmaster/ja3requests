const marker = '<!-- ja3requests-coverage-report -->';

module.exports = async function updateCoverageComment({ github, context, report }) {
  const { owner, repo } = context.repo;
  const issue_number = context.payload.pull_request.number;
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner, repo, issue_number,
  });
  const existing = comments.find(comment =>
    comment.user?.login === 'github-actions[bot]' &&
    comment.body?.startsWith(marker)
  );
  const body = `${marker}\n${report}`;
  if (existing) {
    return github.rest.issues.updateComment({
      owner, repo, comment_id: existing.id, body,
    });
  }
  return github.rest.issues.createComment({ owner, repo, issue_number, body });
};
