const assert = require('node:assert/strict');
const test = require('node:test');
const updateCoverageComment = require('./coverage-comment.cjs');

const marker = '<!-- ja3requests-coverage-report -->';
const context = { repo: { owner: 'owner', repo: 'repo' }, payload: { pull_request: { number: 42 } } };

function client(comments) {
  const calls = [];
  const github = {
    paginate: async (method, args) => {
      assert.deepEqual(args, { owner: 'owner', repo: 'repo', issue_number: 42 });
      return comments;
    },
    rest: { issues: {
      listComments() {},
      createComment: async args => calls.push({ kind: 'create', ...args }),
      updateComment: async args => calls.push({ kind: 'update', ...args }),
    } },
  };
  return { github, calls };
}

test('creates a report without overwriting unrelated bot comments', async () => {
  const { github, calls } = client([
    { id: 1, user: { login: 'github-actions[bot]' }, body: 'Build results' },
  ]);
  await updateCoverageComment({ github, context, report: '87% coverage' });
  assert.deepEqual(calls, [{
    kind: 'create', owner: 'owner', repo: 'repo', issue_number: 42,
    body: `${marker}\n87% coverage`,
  }]);
});

test('updates only the owned marked report, not the last comment or a human copy', async () => {
  const { github, calls } = client([
    { id: 1, user: { login: 'human' }, body: `${marker}\nHuman text` },
    { id: 2, user: { login: 'github-actions[bot]' }, body: `${marker}\nOld coverage` },
    { id: 3, user: { login: 'github-actions[bot]' }, body: 'Other automation' },
  ]);
  await updateCoverageComment({ github, context, report: '88% coverage' });
  assert.deepEqual(calls, [{
    kind: 'update', owner: 'owner', repo: 'repo', comment_id: 2,
    body: `${marker}\n88% coverage`,
  }]);
});
