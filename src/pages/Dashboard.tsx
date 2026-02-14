import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { StatCard, PageHeader, LoadingSpinner, StatusBadge } from "@/components/ui-components";
import { Wallet, TrendingUp, Activity, Users, ArrowDownToLine, Copy, Check } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

export default function Dashboard() {
  const { user } = useAuth();
  const [data, setData] = useState<any>(null);
  const [transactions, setTransactions] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    Promise.all([
      api.getDashboard().catch(() => ({
        walletBalance: 5700,
        totalInvested: 10000,
        activeInvestments: 2,
        referralEarnings: 1500,
        withdrawableBalance: 3700,
        totalRoiEarned: 0,
      })),
      api.getTransactions().catch(() => ({
        investments: [],
        payments: [],
        withdrawals: [],
      })),
    ]).then(([dashData, txData]) => {
      setData(dashData);
      setTransactions(txData);
    }).finally(() => setLoading(false));
  }, []);

  const copyReferral = () => {
    const link = `${window.location.origin}/register?ref=${user?.referralCode || "REF123"}`;
    navigator.clipboard.writeText(link);
    setCopied(true);
    toast.success("Referral link copied!");
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) return <DashboardLayout><LoadingSpinner /></DashboardLayout>;

  const stats = [
    { label: "Wallet Balance", value: `₦${(data?.walletBalance || 0).toLocaleString()}`, icon: <Wallet className="h-5 w-5" /> },
    { label: "Total Invested", value: `₦${(data?.totalInvested || 0).toLocaleString()}`, icon: <TrendingUp className="h-5 w-5" /> },
    { label: "Daily ROI Earned (15%)", value: `₦${(data?.totalRoiEarned || 0).toLocaleString()}`, icon: <ArrowDownToLine className="h-5 w-5" /> },
    { label: "Active Investments", value: String(data?.activeInvestments || 0), icon: <Activity className="h-5 w-5" /> },
    { label: "Referral Earnings", value: `₦${(data?.referralEarnings || 0).toLocaleString()}`, icon: <Users className="h-5 w-5" /> },
  ];

  return (
    <DashboardLayout>
      <PageHeader title="Dashboard" subtitle={`Welcome back, ${user?.fullName || "Investor"}!`} />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        {stats.map((s, i) => (
          <StatCard key={s.label} label={s.label} value={s.value} icon={s.icon} delay={i * 0.08} />
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="gradient-card border border-border rounded-xl p-6 shadow-card"
      >
        <h3 className="font-display font-semibold text-foreground mb-3">Quick Actions</h3>
        <div className="flex flex-wrap gap-3">
          <a
            href="/invest"
            className="px-6 py-3 gradient-primary text-primary-foreground rounded-lg font-medium hover:opacity-90 transition-opacity"
          >
            Invest Now
          </a>
          <a
            href="/withdraw"
            className="px-6 py-3 border border-border text-foreground rounded-lg font-medium hover:bg-secondary transition-all"
          >
            Withdraw
          </a>
          <button
            onClick={copyReferral}
            className="px-6 py-3 border border-primary/30 text-primary rounded-lg font-medium hover:bg-primary/10 transition-all flex items-center gap-2"
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            Copy Referral Link
          </button>
        </div>
      </motion.div>

      {/* Transaction History */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="gradient-card border border-border rounded-xl p-6 shadow-card mt-8"
      >
        <h3 className="font-display font-semibold text-foreground mb-4">Transaction History</h3>
        <Tabs defaultValue="investments">
          <TabsList className="mb-4">
            <TabsTrigger value="investments">Investments</TabsTrigger>
            <TabsTrigger value="payments">Payments</TabsTrigger>
            <TabsTrigger value="withdrawals">Withdrawals</TabsTrigger>
          </TabsList>

          <TabsContent value="investments">
            {(transactions?.investments?.length || 0) === 0 ? (
              <p className="text-sm text-muted-foreground py-4">No investments yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Plan</TableHead>
                      <TableHead>Amount</TableHead>
                      <TableHead>ROI Days</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {transactions.investments.map((inv: any) => (
                      <TableRow key={inv._id}>
                        <TableCell className="font-medium">{inv.planName || inv.planId}</TableCell>
                        <TableCell>₦{(inv.amount || 0).toLocaleString()}</TableCell>
                        <TableCell>{inv.roiDaysCompleted || 0}/5</TableCell>
                        <TableCell><StatusBadge status={inv.status} /></TableCell>
                        <TableCell className="text-muted-foreground text-sm">{inv.createdAt ? new Date(inv.createdAt).toLocaleDateString() : "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>

          <TabsContent value="payments">
            {(transactions?.payments?.length || 0) === 0 ? (
              <p className="text-sm text-muted-foreground py-4">No payments yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Amount</TableHead>
                      <TableHead>Reference</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {transactions.payments.map((pay: any) => (
                      <TableRow key={pay._id}>
                        <TableCell className="font-medium">₦{(pay.amount || 0).toLocaleString()}</TableCell>
                        <TableCell className="text-muted-foreground">{pay.reference || "—"}</TableCell>
                        <TableCell><StatusBadge status={pay.status} /></TableCell>
                        <TableCell className="text-muted-foreground text-sm">{pay.createdAt ? new Date(pay.createdAt).toLocaleDateString() : "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>

          <TabsContent value="withdrawals">
            {(transactions?.withdrawals?.length || 0) === 0 ? (
              <p className="text-sm text-muted-foreground py-4">No withdrawals yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Amount</TableHead>
                      <TableHead>Bank</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {transactions.withdrawals.map((w: any) => (
                      <TableRow key={w._id}>
                        <TableCell className="font-medium">₦{(w.amount || 0).toLocaleString()}</TableCell>
                        <TableCell className="text-muted-foreground">{w.bankName || "—"}</TableCell>
                        <TableCell><StatusBadge status={w.status} /></TableCell>
                        <TableCell className="text-muted-foreground text-sm">{w.createdAt ? new Date(w.createdAt).toLocaleDateString() : "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </motion.div>
    </DashboardLayout>
  );
}
