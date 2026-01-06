import React, { useState, useEffect } from 'react';
import { SidebarProvider } from "@/components/ui/sidebar";
import DashboardSidebar from "@/components/DashboardSidebar";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Shield,
  Lock,
  FileDown,
  FilePieChart,
  FileText,
  AlertTriangle,
  ShieldCheck,
  Clock,
  Filter
} from 'lucide-react';
import { generatePDFReport } from "@/utils/pdfGenerator";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend, LineChart, Line, XAxis, YAxis, CartesianGrid } from 'recharts';

interface Vulnerability {
  id: number;
  type: string;
  severity: string;
  status: string;
  description: string;
  line?: number;
  code?: string;
  cwe_id?: string;
  cwe_name?: string;
  cwe_description?: string;
  cwe_severity?: string;
  mitigation?: string[];
  references?: string[];
  patch?: {
    suggestion: string;
    code: string;
  };
}

interface Statistics {
  total: number;
  patched: number;
  pending: number;
  inProgress: number;
  severityDistribution: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
  };
}

const SEVERITY_COLORS = {
  Critical: "#ef4444",
  High: "#f59e42",
  Medium: "#facc15",
  Low: "#22d3ee"
};

const StatCard = ({ title, value, icon: Icon }: any) => (
  <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-4">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-sm text-gray-400">{title}</p>
        <h4 className="text-2xl font-bold text-gray-200 mt-1">{value}</h4>
      </div>
      <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
        <Icon className="w-5 h-5 text-cyan-400" />
      </div>
    </div>
  </Card>
);

const Report = () => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [statistics, setStatistics] = useState<Statistics>({
    total: 0,
    patched: 0,
    pending: 0,
    inProgress: 0,
    severityDistribution: {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    }
  });
  const [isLoading, setIsLoading] = useState(true);
  const [lastScanDate, setLastScanDate] = useState<string>('');
  const [trendData, setTrendData] = useState<{ timestamp: string, total: number }[]>([]);

  useEffect(() => {
    // Get vulnerabilities from localStorage
    const storedVulnerabilities = localStorage.getItem('analysisResults');
    const history = JSON.parse(localStorage.getItem('analysisHistory') || '[]');
    setTrendData(history);

    if (storedVulnerabilities) {
      try {
        const parsedData = JSON.parse(storedVulnerabilities);
        
        if (parsedData.vulnerabilities && Array.isArray(parsedData.vulnerabilities)) {
          setVulnerabilities(parsedData.vulnerabilities);
          
          // Update statistics
          const newStats = {
            total: parsedData.vulnerabilities.length,
            patched: parsedData.vulnerabilities.filter((v: Vulnerability) => v.status === 'Patched').length,
            pending: parsedData.vulnerabilities.filter((v: Vulnerability) => v.status === 'Pending').length,
            inProgress: 0,
            severityDistribution: {
              Critical: 0,
              High: 0,
              Medium: 0,
              Low: 0
            }
          };

          // Count severity distribution
          parsedData.vulnerabilities.forEach((v: Vulnerability) => {
            const severity = v.severity.charAt(0).toUpperCase() + v.severity.slice(1);
            if (severity in newStats.severityDistribution) {
              newStats.severityDistribution[severity as keyof typeof newStats.severityDistribution]++;
            }
          });

          setStatistics(newStats);
          
          // Set last scan date
          if (parsedData.timestamp) {
            const scanDate = new Date(parsedData.timestamp);
            setLastScanDate(scanDate.toLocaleDateString());
          }
        }
      } catch (err) {
        console.error('Error parsing stored vulnerabilities:', err);
        setError('Failed to load vulnerability data');
      }
    }
    setIsLoading(false);
  }, []);

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    setError(null);
    setSuccess(null);

    try {
      const filename = generatePDFReport();
      setSuccess(`PDF report "${filename}" generated successfully!`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setIsGenerating(false);
      // Clear success/error messages after 3 seconds
      setTimeout(() => {
        setSuccess(null);
        setError(null);
      }, 3000);
    }
  };

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full bg-gradient-to-b from-[#0f1729] to-[#0f1f3d] text-gray-100">
        <DashboardSidebar />
        <main className="flex-1 flex flex-col h-screen overflow-hidden">
          {/* Header */}
          <div className="flex-none p-6 border-b border-cyan-500/10 bg-[#1a2234]/40 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="relative flex items-center justify-center">
                  <Shield className="h-8 w-8 text-cyan-400" />
                  <Lock className="h-4 w-4 text-white absolute" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-cyan-500">Report Generation</h1>
                  <p className="text-gray-400 mt-1">Generate and download vulnerability reports</p>
                </div>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <ScrollArea className="flex-1">
            <div className="max-w-7xl mx-auto p-6 space-y-6">
              {/* Error/Success Messages */}
              {error && (
                <Card className="bg-red-500/10 border border-red-500/20 backdrop-blur-sm p-4">
                  <div className="flex items-center gap-2 text-red-400">
                    <AlertTriangle className="w-5 h-5" />
                    <span>{error}</span>
                  </div>
                </Card>
              )}
              {success && (
                <Card className="bg-green-500/10 border border-green-500/20 backdrop-blur-sm p-4">
                  <div className="flex items-center gap-2 text-green-400">
                    <FileDown className="w-5 h-5" />
                    <span>{success}</span>
                  </div>
                </Card>
              )}

              {/* Report Controls */}
              <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-6">
                <div className="flex justify-center">
                  <Button 
                    className="bg-cyan-500 hover:bg-cyan-600 text-white disabled:opacity-50 disabled:cursor-not-allowed px-8 py-6 text-lg"
                    onClick={handleGenerateReport}
                    disabled={isGenerating}
                  >
                    {isGenerating ? (
                      <>
                        <div className="w-5 h-5 mr-2 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        Generating PDF...
                      </>
                    ) : (
                      <>
                        <FileText className="w-5 h-5 mr-2" />
                        Generate PDF Report
                      </>
                    )}
                  </Button>
                </div>
              </Card>

              {/* Statistics Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                  title="Total Vulnerabilities"
                  value={statistics.total}
                  icon={AlertTriangle}
                />
                <StatCard
                  title="Patched"
                  value={statistics.patched}
                  icon={ShieldCheck}
                />
                <StatCard
                  title="Pending"
                  value={statistics.pending}
                  icon={Clock}
                />
                <StatCard
                  title="Critical Issues"
                  value={statistics.severityDistribution.Critical}
                  icon={FilePieChart}
                />
              </div>

              {/* Charts Section */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-200">Vulnerability Trends</h3>
                  </div>
                  <div className="h-[200px]">
                    <ResponsiveContainer width="100%" height={200}>
                      <LineChart data={trendData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis 
                          dataKey="timestamp" 
                          tickFormatter={(t) => new Date(t).toLocaleDateString()}
                          stroke="#9ca3af"
                          fontSize={10}
                        />
                        <YAxis allowDecimals={false} stroke="#9ca3af" fontSize={10} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a2234', border: '1px solid #06b6d4', borderRadius: '8px' }}
                          labelStyle={{ color: '#06b6d4' }}
                        />
                        <Line 
                          type="monotone" 
                          dataKey="total" 
                          stroke="#06b6d4" 
                          strokeWidth={2}
                          dot={{ fill: '#06b6d4', r: 4 }}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </Card>

                <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-200">Severity Distribution</h3>
                  </div>
                  <div className="h-[200px]">
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={Object.entries(statistics.severityDistribution).map(([key, value]) => ({ name: key, value }))}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          outerRadius={60}
                          label
                        >
                          {Object.keys(statistics.severityDistribution).map((key, idx) => (
                            <Cell key={key} fill={SEVERITY_COLORS[key as keyof typeof SEVERITY_COLORS]} />
                          ))}
                        </Pie>
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a2234', border: '1px solid #06b6d4', borderRadius: '8px' }}
                        />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              </div>

              {/* Report Preview - Detailed Vulnerabilities */}
              <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold text-gray-200">Report Preview</h3>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" className="border-cyan-500/20 hover:bg-cyan-500/10">
                      <Filter className="w-4 h-4 mr-2" />
                      Filter
                    </Button>
                  </div>
                </div>

                {/* Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-[#0f1729]/80 rounded-lg p-4 border border-cyan-500/10">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-gray-200 font-medium">Project Overview</h4>
                        <p className="text-sm text-gray-400 mt-1">
                          Last scan: {lastScanDate || 'N/A'}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#0f1729]/80 rounded-lg p-4 border border-cyan-500/10">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-gray-200 font-medium">Vulnerability Summary</h4>
                        <p className="text-sm text-gray-400 mt-1">
                          {statistics.severityDistribution.Critical} critical, {statistics.pending} pending
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#0f1729]/80 rounded-lg p-4 border border-cyan-500/10">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-gray-200 font-medium">Patch Status</h4>
                        <p className="text-sm text-gray-400 mt-1">
                          {statistics.patched} patched, {statistics.pending} pending
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Detailed Vulnerabilities List */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-lg font-semibold text-gray-200">Vulnerabilities in Report</h4>
                    <span className="text-sm text-gray-400">{vulnerabilities.length} total</span>
                  </div>

                  {isLoading ? (
                    <div className="flex items-center justify-center p-8">
                      <div className="text-cyan-400">Loading vulnerabilities...</div>
                    </div>
                  ) : vulnerabilities.length === 0 ? (
                    <div className="text-center p-8 text-gray-400">
                      No vulnerabilities found. Please analyze code first.
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {vulnerabilities.map((vuln) => (
                        <Card key={vuln.id} className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm overflow-hidden">
                          <div className="p-4">
                            <div className="flex items-start justify-between">
                              <div className="flex items-start gap-3 flex-1">
                                <div className="mt-1">
                                  <AlertTriangle className={`w-5 h-5 ${
                                    vuln.severity === 'Critical' ? 'text-red-500' :
                                    vuln.severity === 'High' ? 'text-orange-500' :
                                    vuln.severity === 'Medium' ? 'text-yellow-500' : 'text-green-500'
                                  }`} />
                                </div>
                                <div className="flex-1">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <h4 className="text-lg font-semibold text-gray-200">
                                      {vuln.type || vuln.description.substring(0, 50)}
                                    </h4>
                                    <span className={`px-2 py-1 rounded text-xs font-semibold ${
                                      vuln.severity === 'Critical' ? 'text-red-500 border-red-500/20 bg-red-500/10' :
                                      vuln.severity === 'High' ? 'text-orange-500 border-orange-500/20 bg-orange-500/10' :
                                      vuln.severity === 'Medium' ? 'text-yellow-500 border-yellow-500/20 bg-yellow-500/10' :
                                      'text-green-500 border-green-500/20 bg-green-500/10'
                                    } border`}>
                                      {vuln.severity}
                                    </span>
                                    <span className={`px-2 py-1 rounded text-xs ${
                                      vuln.status === 'Patched' ? 'text-green-500 bg-green-500/10' :
                                      'text-orange-500 bg-orange-500/10'
                                    }`}>
                                      {vuln.status}
                                    </span>
                                  </div>
                                  <div className="mt-2 text-sm text-gray-400">
                                    {vuln.description}
                                  </div>
                                  <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                                    {vuln.cwe_id && (
                                      <span className="text-cyan-400">CWE: {vuln.cwe_id}</span>
                                    )}
                                    {vuln.line && (
                                      <span>Line {vuln.line}</span>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </div>
                            {vuln.patch && (
                              <div className="mt-4 pt-4 border-t border-cyan-500/10">
                                <div className="text-sm font-semibold text-cyan-400 mb-2">Patch Available</div>
                                <div className="text-xs text-gray-300 bg-[#0f1729]/80 rounded p-3 font-mono">
                                  {vuln.patch.code.substring(0, 100)}...
                                </div>
                              </div>
                            )}
                          </div>
                        </Card>
                      ))}
                    </div>
                  )}
                </div>
              </Card>
            </div>
          </ScrollArea>
        </main>
      </div>
    </SidebarProvider>
  );
};

export default Report; 