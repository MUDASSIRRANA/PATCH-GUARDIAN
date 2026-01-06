
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  Legend,
} from "recharts";
import { Card } from "@/components/ui/card";

const data = [
  { month: "Jan", scans: 20, vulnerabilities: 12, patches: 8 },
  { month: "Feb", scans: 35, vulnerabilities: 22, patches: 18 },
  { month: "Mar", scans: 25, vulnerabilities: 14, patches: 10 },
  { month: "Apr", scans: 45, vulnerabilities: 28, patches: 24 },
  { month: "May", scans: 55, vulnerabilities: 32, patches: 30 },
  { month: "Jun", scans: 40, vulnerabilities: 24, patches: 22 },
  { month: "Jul", scans: 35, vulnerabilities: 20, patches: 19 },
  { month: "Aug", scans: 30, vulnerabilities: 16, patches: 14 },
  { month: "Sep", scans: 35, vulnerabilities: 22, patches: 20 },
  { month: "Oct", scans: 40, vulnerabilities: 26, patches: 25 },
  { month: "Nov", scans: 35, vulnerabilities: 20, patches: 19 },
  { month: "Dec", scans: 45, vulnerabilities: 27, patches: 23 },
];

export function ScanChart() {
  return (
    <Card className="p-6 bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 shadow-lg">
      <h2 className="text-xl font-semibold mb-6 text-cyan-300">Security Monitoring Analytics</h2>
      <div className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#4318FF" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#4318FF" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorVulnerabilities" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#FF5252" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#FF5252" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorPatches" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#05CD99" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#05CD99" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#334155" />
            <XAxis dataKey="month" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1e293b', 
                border: 'none',
                borderRadius: '8px',
                color: '#e2e8f0'
              }} 
            />
            <Legend wrapperStyle={{ color: '#e2e8f0' }} />
            <Area
              type="monotone"
              dataKey="scans"
              stroke="#4318FF"
              fillOpacity={1}
              fill="url(#colorScans)"
              activeDot={{ r: 8, fill: '#4318FF' }}
            />
            <Area
              type="monotone"
              dataKey="vulnerabilities"
              stroke="#FF5252"
              fillOpacity={1}
              fill="url(#colorVulnerabilities)"
              activeDot={{ r: 8, fill: '#FF5252' }}
            />
            <Area
              type="monotone"
              dataKey="patches"
              stroke="#05CD99"
              fillOpacity={1}
              fill="url(#colorPatches)"
              activeDot={{ r: 8, fill: '#05CD99' }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
