# Security Audit of ALX Polly

As a senior programming security expert, I have conducted a thorough review of the ALX Polly codebase. This document outlines the security issues and flaws I have identified, along with recommended fixes for each.

## 1. Authentication & Authorization

### 1.1. Client-Side Redirection After Login

- **File:** `app/(auth)/login/page.tsx`
- **Issue:** The login form uses `window.location.href` for redirection after a successful login. This forces a full page reload, which is inefficient and not the standard Next.js approach. More importantly, client-side redirection can be manipulated and is less secure than server-side redirection for sensitive operations like login.
- **Fix:** Use the `useRouter` hook from `next/navigation` for client-side navigation, or preferably, handle the redirection on the server-side within the `login` server action.

### 1.2. Leaking Implementation Details in Error Messages

- **File:** `app/lib/actions/auth-actions.ts`
- **Issue:** The `login` and `register` functions return error messages directly from the Supabase client. This can leak implementation details about the authentication backend (e.g., "Invalid login credentials" vs. "User not found").
- **Fix:** Return generic error messages to the client, such as "Invalid email or password," to avoid disclosing unnecessary information.

### 1.3. Anonymous Voting

- **File:** `app/lib/actions/poll-actions.ts`
- **Issue:** In the `submitVote` function, user authentication is optional (`user?.id ?? null`). This allows anonymous users to vote, which could lead to vote manipulation.
- **Fix:** If voting should be restricted to authenticated users, enforce this by checking if `user` is null and returning an error if they are not logged in.

## 2. Cross-Site Scripting (XSS)

### 2.1. Improper Encoding in Share Links

- **File:** `app/(dashboard)/polls/vulnerable-share.tsx`
- **Issue:** The `pollTitle` is used to construct `mailto:` and Twitter share links. While `encodeURIComponent` is used, it's crucial to ensure this is sufficient for all contexts. If a poll title contains malicious content, it could be executed when a user clicks the share links.
- **Fix:** Always treat user-generated content as untrusted. In addition to encoding, consider implementing a Content Security Policy (CSP) to mitigate the impact of any potential XSS vulnerabilities.

### 2.2. Rendering User-Generated Content

- **File:** `app/(dashboard)/polls/[id]/page.tsx`
- **Issue:** The poll title and description are rendered directly. Although React escapes content by default, this is a potential risk if the data were ever used with `dangerouslySetInnerHTML`.
- **Fix:** Sanitize all user-generated content on the server before it is stored in the database. This provides a stronger defense against XSS.

## 3. Insecure Direct Object Reference (IDOR)

### 3.1. Lack of Authorization in `getPollById`

- **File:** `app/lib/actions/poll-actions.ts`
- **Issue:** The `getPollById` action fetches a poll by its ID without any authorization checks. This means any user can view any poll if they know the ID. This might be intended, but if polls are meant to be private, this is a vulnerability.
- **Fix:** If polls can be private, add an authorization check to `getPollById` to ensure the current user has permission to view the poll.

### 3.2. "Edit Poll" Button Visible to All Users

- **File:** `app/(dashboard)/polls/[id]/page.tsx`
- **Issue:** The "Edit Poll" button is visible to all users, regardless of whether they created the poll. This can be confusing and lead to a poor user experience.
- **Fix:** Only show the "Edit Poll" button to the user who created the poll. This can be achieved by comparing the current user's ID with the `user_id` of the poll.

## 4. Positive Security Note: CSRF Protection

The application uses Next.js Server Actions, which include built-in CSRF protection. This is a commendable security practice that helps protect against Cross-Site Request Forgery attacks.

## Conclusion

The ALX Polly application has a solid foundation, but there are several security vulnerabilities that need to be addressed. By implementing the recommended fixes, you can significantly improve the security posture of the application.
