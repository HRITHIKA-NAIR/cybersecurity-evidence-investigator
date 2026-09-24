# User guide

Use EVIDENCE to understand suspicious content and find sensible next steps. It is an investigation-support website, not antivirus software or an account-recovery service. Read important findings and their limitations together.

## Create an account and sign in

Choose Sign in in the top bar, then Create an account. Enter an email address and a unique passphrase of at least 12 characters. Confirm that you are an adult and accept the terms after reading the privacy notice. Follow the confirmation email, then sign in. If the service is still being configured, account creation may be unavailable.

Forgot password sends a recovery link. Use the link in the same browser/device that requested it because the authentication flow uses PKCE. Choose a new password and sign in again. My account includes password reset and global sign-out. Previously issued access tokens may remain valid until their expiry; global sign-out revokes refresh sessions.

## Choose what to investigate

Links and websites accepts a complete public HTTP or HTTPS URL. Do not submit a URL containing credentials, access tokens or one-use secrets; the server may contact it.

Emails accepts pasted email text or an original .eml file. A screenshot does not provide the original email headers. If you choose a file, the text input is disabled so the submitted evidence is unambiguous.

Files and QR codes accepts supported documents, archives, script-like files and images up to 10 MiB. View Supported file types for the full list. A file must not be empty. Encrypted or unsupported content may remain inconclusive. Uploaded files are not executed.

Texts and messages accepts the message text with relevant URLs. Remove unrelated personal details, passwords and one-time codes. Submit only evidence you own or have permission to inspect.

## Submit and wait

Read the processing notice, check the acknowledgement and choose Investigate evidence. Sign in first if prompted; signing in can clear a previously filled form for privacy. During analysis, the shield rotates and the form cannot be resubmitted. After 15 seconds, a notice explains that the free service or a provider may be slow.

Keep the page open. If a request times out, check My investigations before trying again because the server may have completed it. Do not interpret a timeout or unavailable check as evidence that the content is safe.

## Read the result

Overview presents the score, verdict, confidence and detected findings. Scores and confidence are generated assessments, not guarantees or calibrated probabilities. Inconclusive means the app cannot make a supported determination. AI is optional and can be disabled.

Supporting evidence shows observations and the evidence-backed sequence. Technical details exposes relevant email, file, URL and reputation checks. Some sections may be empty for the input you chose.

What to do next offers recovery guidance. Confirm the situation you actually experienced. A suspicious attachment finding does not by itself mean you ran malware. Challenge Conclusion requests another assessment of the same evidence and uses another request allowance.

## Revisit and delete cases

Choose My investigations. The latest 100 case previews load automatically. Search checks preview text, case number, type and verdict; it does not search all extracted evidence. Use Refresh to reload the list. Select a case to reopen it. Choose its Delete button, review the warning and confirm Delete permanently to remove it and related active-storage rows.

For account deletion or access requests, use the contact published on Data deletion. Never send passwords or tokens, and never post private evidence in public repository issues.

## Problems and next actions

| What you see | What to do |
| --- | --- |
| You are offline | Reconnect; already-loaded recovery guidance remains readable |
| Session needs attention | Sign in again |
| Permission denied | Confirm your email; use the account that owns the case |
| Request limit reached | Wait for the stated retry period; do not create accounts to bypass limits |
| PostgreSQL or history unavailable | Retry later and contact the operator without including secrets |
| No search matches | Clear the search or try a different term |
| Result was not saved | Preserve only what you are authorized to retain; check service status before leaving |

Use the theme slider for light or dark mode. Keyboard users can begin with Skip to main content. Reduced-motion settings in your operating system turn off decorative motion.

If credentials were stolen, use the real provider's official app from a trusted device and secure your main email first. If money was sent, contact the bank immediately through its official channel. If a work device is affected, involve its security team.
