
import { Card } from "@/components/ui/card";
import { LineChart, Line, ResponsiveContainer, Tooltip } from "recharts";

interface MetricCardProps {
  title: string;
  value: string | number;
  trend: number;
  data: { value: number }[];
  trendColor: string;
  icon?: React.ReactNode;
}

export function MetricCard({ title, value, trend, data, trendColor, icon }: MetricCardProps) {
  return (
    <Card className="p-6 animate-fade-in bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 shadow-lg">
      <div className="flex justify-between items-start mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            {icon && <div className="text-cyan-400">{icon}</div>}
            <h3 className="text-sm text-cyan-300 font-medium">{title}</h3>
          </div>
          <p className="text-2xl font-semibold mt-1 text-white">{value}</p>
        </div>
        <span className={`text-sm font-medium px-2 py-1 rounded-full ${trend >= 0 ? "bg-green-900/50 text-green-400" : "bg-red-900/50 text-red-400"}`}>
          {trend > 0 ? "+" : ""}{trend}%
        </span>
      </div>
      <div className="h-16">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1e293b', 
                border: 'none',
                borderRadius: '8px',
                color: '#e2e8f0'
              }} 
            />
            <Line
              type="monotone"
              dataKey="value"
              stroke={trendColor}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, fill: trendColor }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
