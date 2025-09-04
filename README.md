# AI Security Engineer Audit of ALX Polly

As an AI security engineer, I have conducted a thorough review of the ALX Polly codebase. This document outlines the security issues and flaws identified, along with code-level recommendations for fixing them.

---

## 1. Authentication & Authorization Vulnerabilities

### 1.1. Insecure Client-Side Redirection After Login

- **File:** `app/(auth)/login/page.tsx`
- **Vulnerability:** The login form uses `window.location.href` for redirection. This is an insecure practice because the redirection occurs on the client-side, which can be manipulated. It also forces an unnecessary full-page reload.
- **Impact:** A malicious actor could potentially intercept and modify the client-side script to redirect a user to a phishing site after login.
- **Proposed Fix:** Replace the client-side redirect with `useRouter` from `next/navigation` for smoother, safer client-side transitions. The `router.refresh()` method should be called to ensure the new session state is reflected.

  ```diff
  --- a/app/(auth)/login/page.tsx
  +++ b/app/(auth)/login/page.tsx
  @@ -1,6 +1,7 @@
   'use client';

   import { useState } from 'react';
  +import { useRouter } from 'next/navigation';
   import Link from 'next/link';
   import { Button } from '@/components/ui/button';
   import { Input } from '@/components/ui/input';
  @@ -10,6 +11,7 @@

   export default function LoginPage() {
     const [error, setError] = useState<string | null>(null);
  +  const router = useRouter();
     const [loading, setLoading] = useState(false);

     const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
  @@ -26,7 +28,8 @@
       setError(result.error);
       setLoading(false);
     } else {
  -    window.location.href = '/polls'; // Full reload to pick up session
  +    router.push('/polls');
  +    router.refresh(); // Ensures the session is picked up
     }
   };
  ```

### 1.2. Leaking Implementation Details in Error Messages

- **File:** `app/lib/actions/auth-actions.ts`
- **Vulnerability:** The `login` and `register` server actions return raw error messages from the Supabase backend.
- **Impact:** This information leakage can help an attacker understand the underlying technology stack and database schema, allowing them to craft more targeted attacks. For example, knowing whether a user exists or not simplifies account enumeration attacks.
- **Proposed Fix:** Abstract the backend errors into generic messages. This prevents leaking sensitive details while still providing useful feedback to the user.

  ```diff
  --- a/app/lib/actions/auth-actions.ts
  +++ b/app/lib/actions/auth-actions.ts
  @@ -9,7 +9,8 @@
     });

     if (error) {
  -    return { error: error.message };
  +    // Return a generic error message to avoid leaking implementation details
  +    return { error: 'Invalid email or password.' };
     }

     // Success: no error
  @@ -28,7 +29,8 @@
     });

     if (error) {
  -    return { error: error.message };
  +    // Return a generic error message
  +    return { error: 'Could not create user. Please try again.' };
     }

     // Success: no error
  ```

### 1.3. Unauthenticated Voting and Vote Manipulation

- **File:** `app/lib/actions/poll-actions.ts`
- **Vulnerability:** The `submitVote` action allows unauthenticated users to vote by assigning `null` to `user_id`. Furthermore, there is no check to prevent a single user from voting multiple times.
- **Impact:** This allows for trivial vote manipulation. A malicious actor could write a simple script to cast an unlimited number of votes, completely compromising the integrity of the polls.
- **Proposed Fix:** Enforce that only authenticated users can vote. Additionally, before inserting a new vote, check if the user has already voted on that specific poll.

  ```diff
  --- a/app/lib/actions/poll-actions.ts
  +++ b/app/lib/actions/poll-actions.ts
  @@ -80,18 +80,34 @@
     data: { user },
   } = await supabase.auth.getUser();

  -  // Optionally require login to vote
  -  // if (!user) return { error: 'You must be logged in to vote.' };
  +  // Enforce that only authenticated users can vote
  +  if (!user) {
  +    return { error: 'You must be logged in to vote.' };
  +  }
  +
  +  // Check if the user has already voted on this poll
  +  const { data: existingVote, error: voteCheckError } = await supabase
  +    .from('votes')
  +    .select('id')
  +    .eq('poll_id', pollId)
  +    .eq('user_id', user.id)
  +    .single();
  +
  +  if (voteCheckError && voteCheckError.code !== 'PGRST116') { // 'PGRST116' means no rows found
  +    return { error: 'Error checking for existing vote.' };
  +  }
  +
  +  if (existingVote) {
  +    return { error: 'You have already voted on this poll.' };
  +  }

     const { error } = await supabase.from("votes").insert([
       {
         poll_id: pollId,
  -      user_id: user?.id ?? null,
  +      user_id: user.id,
         option_index: optionIndex,
       },
     ]);
  ```

---

## 2. Insecure Direct Object Reference (IDOR)

### 2.1. Lack of Ownership Check for Sensitive Actions

- **File:** `app/(dashboard)/polls/[id]/page.tsx`
- **Vulnerability:** The "Edit Poll" and "Delete" buttons are displayed to any user viewing a poll, regardless of whether they are the owner. While the backend `updatePoll` action correctly checks for ownership, the UI incorrectly suggests that these actions are available to everyone.
- **Impact:** This is a UI-level flaw that can lead to a confusing and frustrating user experience. It also signals a potential lack of server-side validation (even though it exists in this case), which can encourage attackers to probe for deeper authorization flaws.
- **Proposed Fix:** The page should fetch the current user's session and compare their ID with the poll's `user_id`. The "Edit" and "Delete" controls should only be rendered if the user is the owner of the poll.

```diff
--- a/app/(dashboard)/polls/[id]/page.tsx
+++ b/app/(dashboard)/polls/[id]/page.tsx
@@ -1,6 +1,7 @@
 'use client';

-import { useState } from 'react';
+import { useState, useEffect } from 'react';
+import { getCurrentUser } from '@/app/lib/actions/auth-actions';
 import Link from 'next/link';
 import { Button } from '@/components/ui/button';
 import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
@@ -17,10 +18,23 @@
    createdBy: 'John Doe',
 };

-export default function PollDetailPage({ params }: { params: { id: string } }) {
+export default function PollDetailPage({ params }: { params: { id: string } }) {
    const [selectedOption, setSelectedOption] = useState<string | null>(null);
    const [hasVoted, setHasVoted] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
+  const [isOwner, setIsOwner] = useState(false);
+  const [user, setUser] = useState<any>(null);
+
+  useEffect(() => {
+    const checkOwnership = async () => {
+      const currentUser = await getCurrentUser();
+      setUser(currentUser);
+      // Replace '123' with actual poll.owner id from fetched poll data
+      if (currentUser && currentUser.id === '123') {
+        setIsOwner(true);
+      }
+    };
+    checkOwnership();
+  }, []);

    // In a real app, you would fetch the poll data based on the ID
    const poll = mockPoll;
@@ -44,14 +58,16 @@
      <div className="flex items-center justify-between">
         <Link href="/polls" className="text-blue-600 hover:underline">
            &larr; Back to Polls
         </Link>
-      <div className="flex space-x-2">
-        <Button variant="outline" asChild>
-          <Link href={`/polls/${params.id}/edit`}>Edit Poll</Link>
-        </Button>
-        <Button variant="outline" className="text-red-500 hover:text-red-700">
-          Delete
-        </Button>
-      </div>
+      {isOwner && (
+        <div className="flex space-x-2">
+          <Button variant="outline" asChild>
+            <Link href={`/polls/${params.id}/edit`}>Edit Poll</Link>
+          </Button>
+          <Button variant="outline" className="text-red-500 hover:text-red-700">
+            Delete
+          </Button>
+        </div>
+      )}
      </div>

      <Card>
```

## Conclusion

The ALX Polly application provides an excellent learning opportunity for identifying common web security vulnerabilities. The issues identified—ranging from insecure redirection and information leakage to authorization flaws—are representative of real-world security bugs. By implementing the proposed fixes, the application's security posture can be significantly hardened, ensuring data integrity and protecting user accounts.
