import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { PageHeader, LoadingSpinner, StatusBadge } from "@/components/ui-components";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";

const mockUsers = [
  { id: "1", fullName: "Adebayo Johnson", email: "adebayo@email.com", walletBalance: 5700, totalInvested: 10000, status: "active" },
  { id: "2", fullName: "Chioma Okafor", email: "chioma@email.com", walletBalance: 12300, totalInvested: 25000, status: "active" },
  { id: "3", fullName: "Emeka Uche", email: "emeka@email.com", walletBalance: 800, totalInvested: 5000, status: "blocked" },
];

export default function AdminUsers() {
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAdminUsers()
      .then((d: any) => setUsers(d.users || d))
      .catch(() => setUsers(mockUsers))
      .finally(() => setLoading(false));
  }, []);

  const toggleBlock = async (userId: string) => {
    try {
      await api.toggleUserBlock(userId);
      setUsers((prev) => prev.map((u) => u.id === userId ? { ...u, status: u.status === "blocked" ? "active" : "blocked" } : u));
      toast.success("User status updated");
    } catch {
      setUsers((prev) => prev.map((u) => u.id === userId ? { ...u, status: u.status === "blocked" ? "active" : "blocked" } : u));
      toast.info("User status toggled (demo)");
    }
  };

  if (loading) return <DashboardLayout><LoadingSpinner /></DashboardLayout>;

  return (
    <DashboardLayout>
      <PageHeader title="Users Management" subtitle="View and manage platform users" />
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Name</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Email</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Wallet</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Invested</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Status</th>
              <th className="text-left py-3 px-4 text-xs text-muted-foreground font-medium uppercase">Action</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u, i) => (
              <motion.tr key={u.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }} className="border-b border-border/50 hover:bg-secondary/50 transition-colors">
                <td className="py-3 px-4 text-sm font-medium text-foreground">{u.fullName}</td>
                <td className="py-3 px-4 text-sm text-muted-foreground">{u.email}</td>
                <td className="py-3 px-4 text-sm text-foreground">₦{(u.walletBalance || 0).toLocaleString()}</td>
                <td className="py-3 px-4 text-sm text-foreground">₦{(u.totalInvested || 0).toLocaleString()}</td>
                <td className="py-3 px-4"><StatusBadge status={u.status === "blocked" ? "blocked" : "confirmed"} /></td>
                <td className="py-3 px-4">
                  <button
                    onClick={() => toggleBlock(u.id)}
                    className={`text-xs font-medium px-3 py-1.5 rounded-lg transition-all ${
                      u.status === "blocked"
                        ? "bg-success/10 text-success hover:bg-success/20"
                        : "bg-destructive/10 text-destructive hover:bg-destructive/20"
                    }`}
                  >
                    {u.status === "blocked" ? "Unblock" : "Block"}
                  </button>
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
}
