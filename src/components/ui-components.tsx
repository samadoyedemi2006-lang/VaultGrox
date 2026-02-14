import { ReactNode } from "react";
import { motion } from "framer-motion";

interface StatusBadgeProps {
  status: string;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const styles: Record<string, string> = {
    pending: "bg-warning/20 text-warning",
    confirmed: "bg-success/20 text-success",
    completed: "bg-success/20 text-success",
    paid: "bg-success/20 text-success",
    approved: "bg-success/20 text-success",
    rejected: "bg-destructive/20 text-destructive",
    blocked: "bg-destructive/20 text-destructive",
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold capitalize ${styles[status] || "bg-muted text-muted-foreground"}`}>
      {status}
    </span>
  );
}

interface StatCardProps {
  label: string;
  value: string;
  icon: ReactNode;
  delay?: number;
}

export function StatCard({ label, value, icon, delay = 0 }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="gradient-card rounded-xl p-6 border border-border shadow-card"
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-muted-foreground text-sm">{label}</span>
        <div className="text-primary">{icon}</div>
      </div>
      <p className="text-2xl font-display font-bold text-foreground">{value}</p>
    </motion.div>
  );
}

export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="h-8 w-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

export function PageHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-8">
      <h1 className="text-2xl md:text-3xl font-display font-bold text-foreground">{title}</h1>
      {subtitle && <p className="text-muted-foreground mt-1">{subtitle}</p>}
    </div>
  );
}
