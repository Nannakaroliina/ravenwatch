# Terms of Use

Last updated: 29 October 2026

These terms apply to your use of ravenwatch, a free, open-source plugin for Claude Code made by Nanna Karoliina ("I", "me"). By installing or using ravenwatch you agree to them.

## Licence

ravenwatch is released under the [MIT License](LICENSE). You may use, copy, modify and distribute it under that licence. If anything in these terms conflicts with the MIT License, the MIT License wins.

## What ravenwatch is, and what it isn't

ravenwatch is an aid to reviewing your own code before you push it. It is not a guarantee:

- **Reviews can miss things and can be wrong.** Findings come from AI agents and pattern scans. A passing review does not mean your code is free of bugs, vulnerabilities, leaked secrets or privacy problems, and a finding may be a false alarm. You remain responsible for the code you write, push and deploy.
- **The push gate guards against accidents, not attackers.** It runs on your machine as you, and can be bypassed (for example with `git push --no-verify`). Use branch protection on your git host for real enforcement.
- **It is not professional advice.** Security, privacy or GDPR findings are not legal, compliance or security-audit advice.

## Your responsibilities

- Use ravenwatch only on code you have the right to review and to send to Claude.
- Review the check commands in your project brief before approving them: ravenwatch runs them on your machine as you.
- Your use of Claude Code, and the code you share with Claude through it, is governed by your own agreement with Anthropic (see [Anthropic's terms](https://www.anthropic.com/legal)). ravenwatch is not made, endorsed or supported by Anthropic.
- Keep your own backups. ravenwatch only writes inside `.git/ravenwatch/` and the hook it installs, but you are responsible for your repositories.

## No warranty and limitation of liability

ravenwatch is provided "as is", without warranty of any kind, as set out in the MIT License. To the fullest extent the law allows, I am not liable for any damage, loss of data, security incident, cost or other harm arising from using or not being able to use ravenwatch, including anything a review missed or a push the gate allowed or refused. Nothing in these terms limits liability that cannot be limited by law.

## Support

ravenwatch is maintained in my own time. I aim to respond to issues at <https://github.com/Nannakaroliina/ravenwatch/issues> but can't promise a response time or fix. Please don't describe a security problem in a public issue: open an issue asking for a private contact first.

## Changes

I may update these terms. The current version is always this file in the repository, with its date at the top; the repository's history keeps every earlier version. Continuing to use ravenwatch after a change means you accept the updated terms.

## Privacy

How ravenwatch handles data is described in the [Privacy Policy](PRIVACY.md).

## Contact

Questions about these terms: open an issue at <https://github.com/Nannakaroliina/ravenwatch/issues>.
