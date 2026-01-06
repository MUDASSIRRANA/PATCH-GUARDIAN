
import React from 'react';
import { Area, AreaChart, ResponsiveContainer, XAxis, YAxis, Tooltip } from 'recharts';
import {MetricCard} from '@/components/MetricCard';
import { Code, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { Link } from "react-router-dom"; // <-- add this import


// Sample data for the metrics
const generateChartData = (count: number) => {
  return Array.from({ length: count }, (_, i) => ({
    value: Math.floor(Math.random() * 50) + 20
  }));
};

const monthlyData = [
  { name: 'Jan', scans: 20, vulnerabilities: 15, patches: 12 },
  { name: 'Feb', scans: 25, vulnerabilities: 18, patches: 15 },
  { name: 'Mar', scans: 22, vulnerabilities: 13, patches: 16 },
  { name: 'Apr', scans: 30, vulnerabilities: 28, patches: 22 },
  { name: 'May', scans: 45, vulnerabilities: 30, patches: 25 },
  { name: 'Jun', scans: 40, vulnerabilities: 28, patches: 26 },
  { name: 'Jul', scans: 35, vulnerabilities: 25, patches: 20 },
  { name: 'Aug', scans: 32, vulnerabilities: 22, patches: 18 },
  { name: 'Sep', scans: 40, vulnerabilities: 30, patches: 25 },
  { name: 'Oct', scans: 42, vulnerabilities: 28, patches: 26 },
  { name: 'Nov', scans: 40, vulnerabilities: 25, patches: 28 },
  { name: 'Dec', scans: 45, vulnerabilities: 30, patches: 32 },
];

const Dashboard = () => {
  const metrics = [
    {
      title: 'Code Scanned',
      value: '50',
      change: '35.6%',
      isPositive: true,
      data: generateChartData(12),
      color: '#3B82F6',
      icon: <Code className="text-blue-500" size={20} />
    },
    {
      title: 'Vulnerabilities',
      value: '290+',
      change: '20.4%',
      isPositive: false,
      data: generateChartData(12),
      color: '#EF4444',
      icon: <AlertTriangle className="text-red-500" size={20} />
    },
    {
      title: 'Total Risks',
      value: '23',
      change: '30.6%',
      isPositive: true,
      data: generateChartData(12),
      color: '#10B981',
      icon: <Shield className="text-green-500" size={20} />
    },
    {
      title: 'Patch Success',
      value: '86%',
      change: '12.5%',
      isPositive: true,
      data: generateChartData(12),
      color: '#06B6D4',
      icon: <CheckCircle className="text-cyan-500" size={20} />
    }
  ];

  return (
    <div className="p-8 bg-background min-h-screen">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-white mb-2">Patch Guardians</h1>
        <p className="text-gray-400">Welcome to your security overview</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
  {metrics.map((metric, index) => (
    <Link to="/dashboard/codeanalysis" key={index}>
    <MetricCard {...metric} />
  </Link>
  
  ))}
</div>


      <div className="bg-slate-900/50 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-6">Security Monitoring Analytics</h2>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={monthlyData}>
              <defs>
                <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.1}/>
                </linearGradient>
                <linearGradient id="vulnGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.1}/>
                </linearGradient>
                <linearGradient id="patchGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10B981" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#10B981" stopOpacity={0.1}/>
                </linearGradient>
              </defs>
              <XAxis 
                dataKey="name" 
                stroke="#64748B"
                tick={{ fill: '#64748B' }}
              />
              <YAxis 
                stroke="#64748B"
                tick={{ fill: '#64748B' }}
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1E293B',
                  borderColor: '#3F3F46',
                  borderRadius: '6px'
                }}
              />
              <Area
                type="monotone"
                dataKey="scans"
                stackId="1"
                stroke="#3B82F6"
                fill="url(#scanGradient)"
              />
              <Area
                type="monotone"
                dataKey="vulnerabilities"
                stackId="1"
                stroke="#06B6D4"
                fill="url(#vulnGradient)"
              />
              <Area
                type="monotone"
                dataKey="patches"
                stackId="1"
                stroke="#10B981"
                fill="url(#patchGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;