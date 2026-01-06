import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import DashboardSidebar from '@/components/DashboardSidebar'; // Correct import

import { MetricCard } from "@/components/MetricCard";
import { ScanChart } from "@/components/ScanChart";
import { Logo } from "@/components/Logo";
//import { LLMPatchSection } from "@/components/LLMPatchSection";
import { Plus, Shield, AlertTriangle, Code, Bell, Activity } from "lucide-react";

const metricData = [
  {
    title: "Code Scanned",
    value: "50",
    trend: 35.6,
    data: Array.from({ length: 10 }, () => ({ value: Math.random() * 100 })),
    trendColor: "#4318FF",
    icon: <Code className="h-4 w-4" />
  },
  {
    title: "Vulnerabilities",
    value: "290+",
    trend: -20.4,
    data: Array.from({ length: 10 }, () => ({ value: Math.random() * 100 })),
    trendColor: "#FF5252",
    icon: <AlertTriangle className="h-4 w-4" />
  },
  {
    title: "Total Risks",
    value: "23",
    trend: 30.6,
    data: Array.from({ length: 10 }, () => ({ value: Math.random() * 100 })),
    trendColor: "#05CD99",
    icon: <Shield className="h-4 w-4" />
  },
  {
    title: "Patch Success",
    value: "86%",
    trend: 12.5,
    data: Array.from({ length: 10 }, () => ({ value: Math.random() * 100 })),
    trendColor: "#00CFDD",
    icon: <Code className="h-4 w-4" />
  },
];

const Index = () => {
  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full bg-slate-950 text-gray-100">
        <DashboardSidebar />
        <main className="flex-1 p-8">
          <div className="flex justify-between items-center mb-8">
            <div className="flex flex-col gap-1">
              <Logo />
              <p className="text-gray-400 ml-1">Welcome to your security overview</p>
            </div>
            <SidebarTrigger />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {metricData.map((metric, index) => (
              <MetricCard key={index} {...metric} />
            ))}
          </div>

          <div className="grid gap-6">
            <ScanChart />
             {/* <LLMPatchSection />*/}

          </div>
        </main>
      </div>
    </SidebarProvider>
  );
};

export default Index;
