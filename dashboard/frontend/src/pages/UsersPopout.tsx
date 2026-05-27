import Users from './Users'

/**
 * Standalone full-window mount of the Users page. Routed at /users-popout
 * outside AppShell so the sidebar/top-bar don't render, giving operators a
 * focused workspace they can drag to a second monitor.
 */
export default function UsersPopout() {
  return (
    <div className="min-h-screen bg-background text-foreground p-4">
      <Users />
    </div>
  )
}
