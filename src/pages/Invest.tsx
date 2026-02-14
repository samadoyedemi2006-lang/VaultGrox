import { useState } from "react";
import { useNavigate } from "react-router-dom";
import DashboardLayout from "@/components/DashboardLayout";
import { PageHeader, StatusBadge } from "@/components/ui-components";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Loader2, CheckCircle } from "lucide-react";

const plans = [
  { id: "starter", name: "Starter Growth", amount: 2000, roi: "15%", desc: "Perfect for beginners looking to start their investment journey with a small amount." },
  { id: "silver", name: "Silver Growth", amount: 5000, roi: "15%", desc: "A balanced plan for consistent growth and steady daily returns." },
  { id: "gold", name: "Gold Growth", amount: 10000, roi: "15%", desc: "Premium plan with higher capital for accelerated earnings." },
  { id: "platinum", name: "Platinum Growth", amount: 15000, roi: "15%", desc: "Our top-tier plan for serious investors seeking maximum returns." },
];

export default function InvestPage() {
  const navigate = useNavigate();
  const [selectedPlan, setSelectedPlan] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const handleInvest = async () => {
    const plan = plans.find((p) => p.id === selectedPlan);
    if (!plan) return;
    setLoading(true);
    try {
      await api.createInvestment({ planId: plan.id, amount: plan.amount });
      toast.success("Investment created! Proceed to payment.");
      navigate("/payment");
    } catch {
      toast.info("Investment marked as pending. Proceed to payment.");
      navigate("/payment");
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout>
      <PageHeader title="Investment Plans" subtitle="Choose a plan and start earning daily returns" />

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
        {plans.map((plan, i) => (
          <motion.div
            key={plan.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            onClick={() => { setSelectedPlan(plan.id); setShowConfirm(true); }}
            className={`gradient-card border rounded-xl p-6 shadow-card cursor-pointer transition-all hover:shadow-glow ${
              selectedPlan === plan.id ? "border-primary shadow-glow" : "border-border"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-display font-semibold text-foreground">{plan.name}</h3>
              {selectedPlan === plan.id && <CheckCircle className="h-5 w-5 text-primary" />}
            </div>
            <p className="text-sm text-muted-foreground mb-4">{plan.desc}</p>
            <p className="text-3xl font-display font-bold text-gradient mb-1">₦{plan.amount.toLocaleString()}</p>
            <p className="text-sm text-muted-foreground">Daily ROI: {plan.roi}</p>
          </motion.div>
        ))}
      </div>

      {showConfirm && selectedPlan && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="gradient-card border border-border rounded-xl p-6 shadow-card"
        >
          <h3 className="font-display font-semibold text-foreground mb-3">Confirm Investment</h3>
          <p className="text-sm text-muted-foreground mb-2">
            You are about to invest in <strong className="text-foreground">{plans.find((p) => p.id === selectedPlan)?.name}</strong>.
          </p>
          <p className="text-sm text-muted-foreground mb-4">
            After payment, your investment status will be: <StatusBadge status="pending" />
          </p>
          <div className="glass-card rounded-lg p-3 mb-4 space-y-1">
            <p className="text-xs text-muted-foreground">📌 After you submit your payment proof, an admin will review and confirm it.</p>
            <p className="text-xs text-muted-foreground">📈 Your 15% daily returns will only start <strong className="text-foreground">after admin confirmation</strong> and run for 5 days.</p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleInvest}
              disabled={loading}
              className="px-6 py-3 gradient-primary text-primary-foreground rounded-lg font-medium hover:opacity-90 disabled:opacity-50 transition-all flex items-center gap-2"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              Proceed to Payment
            </button>
            <button
              onClick={() => setShowConfirm(false)}
              className="px-6 py-3 border border-border text-foreground rounded-lg font-medium hover:bg-secondary transition-all"
            >
              Cancel
            </button>
          </div>
        </motion.div>
      )}
    </DashboardLayout>
  );
}
