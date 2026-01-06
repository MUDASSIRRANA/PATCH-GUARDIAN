import React, { useState, useEffect, useRef } from 'react';
import { SidebarProvider } from "@/components/ui/sidebar";
import DashboardSidebar from "@/components/DashboardSidebar";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Shield,
  Lock,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowUpRight,
  ChevronRight,
  BarChart3,
  PieChart,
  Activity,
  Copy,
  Check,
  Play,
  Loader2,
  Zap
} from 'lucide-react';
import { PieChart as RePieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer as ReResponsiveContainer, Legend as ReLegend, LineChart as ReLineChart, Line, XAxis, YAxis, CartesianGrid } from 'recharts';

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
  complete_fixed_code?: string;  // Complete vulnerability-free code
  testResults?: {
    success: boolean;
    is_safe: boolean;
    message: string;
    test_results: {
      compiled: boolean;
      executed: boolean;
      timeout: boolean;
      runtime_error: boolean;
      output: string;
      error: string;
      exit_code: number;
      execution_time: number;
    };
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

interface VulnerabilityCardProps {
  vulnerability: Vulnerability;
  onApplyPatch: () => void;
  onTestPatch?: (vulnerabilityId: number) => Promise<void>;
}

const VulnerabilityCard: React.FC<VulnerabilityCardProps> = ({ vulnerability, onApplyPatch, onTestPatch }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  
  // Use testResults from vulnerability prop, with local state as fallback
  const testResults = vulnerability.testResults;

  const getSeverityColor = (severity: string) => {
    const colors = {
      Critical: "text-red-500 border-red-500/20 bg-red-500/10",
      High: "text-orange-500 border-orange-500/20 bg-orange-500/10",
      Medium: "text-yellow-500 border-yellow-500/20 bg-yellow-500/10",
      Low: "text-green-500 border-green-500/20 bg-green-500/10"
    };
    return colors[severity as keyof typeof colors] || colors.Low;
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "Patched":
        return <CheckCircle2 className="w-4 h-4 text-green-500" />;
      case "Pending":
        return <Clock className="w-4 h-4 text-orange-500" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
    }
  };

  return (
    <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className="mt-1">
              <AlertTriangle className={`w-5 h-5 ${getSeverityColor(vulnerability.severity).split(' ')[0]}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-semibold text-gray-200">{vulnerability.type || vulnerability.description}</h3>
                <Badge variant="outline" className={`${getSeverityColor(vulnerability.severity)}`}>{vulnerability.severity}</Badge>
              </div>
              <div className="flex items-center gap-2 mt-1 text-sm text-gray-400">
                {vulnerability.cwe_id && <code className="text-cyan-400">{vulnerability.cwe_id}</code>}
                {vulnerability.status && <><span>•</span><div className="flex items-center gap-1">{getStatusIcon(vulnerability.status)}<span>{vulnerability.status}</span></div></>}
              </div>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="text-cyan-400 hover:text-cyan-300"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            <ChevronRight className={`w-5 h-5 transition-transform duration-200 ${isExpanded ? 'rotate-90' : ''}`} />
          </Button>
        </div>

        {isExpanded && (
          <div className="mt-4 space-y-4">
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-gray-300">Vulnerability Details</h4>
              <div className="rounded-lg border border-cyan-500/10 bg-[#0f1729]/80 p-3 space-y-1">
                {vulnerability.line && <div className="text-xs text-cyan-400 font-mono">Line {vulnerability.line}: <span className="text-white">{vulnerability.code}</span></div>}
                <div className="text-base text-gray-200 mt-1">{vulnerability.description}</div>
              </div>
            </div>
            {vulnerability.cwe_id && (
              <div className="p-4 rounded-lg bg-cyan-950/60 border border-cyan-700/30">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="text-cyan-400" size={16} />
                  <span className="font-semibold text-cyan-300">CWE Information</span>
                </div>
                <div className="text-xs text-cyan-400 mb-1">
                  <strong>CWE:</strong> <span className="font-bold">{vulnerability.cwe_id}</span> - <span className="font-semibold">{vulnerability.cwe_name}</span>
                </div>
                <div className="text-xs text-gray-300 mb-2">{vulnerability.cwe_description}</div>
                <div className="text-xs text-cyan-300 mb-1"><strong>CWE Severity:</strong> <span className="font-semibold">{vulnerability.cwe_severity}</span></div>
                <div className="text-xs text-cyan-300 mb-1 flex items-center gap-1">
                  <Lock className="inline-block text-cyan-400" size={13} />
                  <strong>Mitigation:</strong>
                </div>
                <ul className="list-disc list-inside ml-4 mb-2 text-xs text-gray-200">
                  {vulnerability.mitigation && vulnerability.mitigation.map((m: string, idx: number) => <li key={idx}>{m}</li>)}
                </ul>
                {vulnerability.references && vulnerability.references.length > 0 && (
                  <div className="text-xs text-cyan-300 mt-2">
                    <strong>References:</strong>
                    <ul className="list-disc list-inside ml-4">
                      {vulnerability.references.map((ref: string, idx: number) => (
                        <li key={idx}><a href={ref} target="_blank" rel="noopener noreferrer" className="underline text-cyan-400 hover:text-cyan-200">{ref}</a></li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
            {vulnerability.patch && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium text-gray-300">Suggested Patch</h4>
                </div>
                <div className="rounded-lg border border-cyan-500/10 bg-[#0f1729]/80 p-3">
                  <p className="text-sm text-gray-400 mb-2">{vulnerability.patch.suggestion}</p>
                  <pre className="text-sm text-cyan-300 whitespace-pre-wrap font-mono overflow-x-auto">
{vulnerability.patch.code}
                  </pre>
                </div>
                
              </div>
            )}
            {vulnerability.complete_fixed_code && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium text-gray-300">Complete Vulnerability-Free Code</h4>
                  <Button
                    variant="outline"
                    size="sm"
                    className="bg-cyan-500 text-white border-cyan-500 hover:bg-cyan-600 hover:border-cyan-600 hover:text-white"
                    onClick={() => {
                      navigator.clipboard.writeText(vulnerability.complete_fixed_code || '');
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                  >
                    {copied ? (
                      <>
                        <Check className="w-4 h-4 mr-1" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="w-4 h-4 mr-1" />
                        Copy Code
                      </>
                    )}
                  </Button>
                </div>
                <div className="rounded-lg border border-cyan-500/20 bg-[#0f1729]/80 p-3 relative">
                  <pre className="text-sm text-cyan-300 whitespace-pre-wrap font-mono overflow-x-auto max-h-96 overflow-y-auto">
{vulnerability.complete_fixed_code}
                  </pre>
                </div>
                {onTestPatch && (
                  <div className="flex justify-end">
                    <Button
                      variant="outline"
                      size="sm"
                      className="bg-cyan-500 text-white border-cyan-500 hover:bg-cyan-600 hover:border-cyan-600 hover:text-white"
                      onClick={async () => {
                        setIsTesting(true);
                        try {
                          await onTestPatch(vulnerability.id);
                        } finally {
                          setIsTesting(false);
                        }
                      }}
                      disabled={isTesting}
                    >
                      {isTesting ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-1 animate-spin" />
                          Testing...
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4 mr-1" />
                          Test Patch
                        </>
                      )}
                    </Button>
                  </div>
                )}
                {testResults && (
                  <div className={`rounded-lg border p-3 ${
                    testResults.is_safe 
                      ? 'border-green-500/20 bg-green-500/10' 
                      : 'border-red-500/20 bg-red-500/10'
                  }`}>
                    <div className="flex items-center gap-2 mb-2">
                      {testResults.is_safe ? (
                        <CheckCircle2 className="w-5 h-5 text-green-400" />
                      ) : (
                        <XCircle className="w-5 h-5 text-red-400" />
                      )}
                      <h5 className="text-sm font-semibold text-gray-200">
                        Runtime Test Results
                      </h5>
                    </div>
                    <p className={`text-sm mb-2 ${
                      testResults.is_safe ? 'text-green-300' : 'text-red-300'
                    }`}>
                      {testResults.message}
                    </p>
                    <div className="space-y-1 text-xs text-gray-300">
                      <div className="flex items-center gap-2">
                        <span>Compiled:</span>
                        <Badge variant="outline" className={
                          testResults.test_results?.compiled 
                            ? 'bg-green-500/20 text-green-400 border-green-500/30' 
                            : 'bg-red-500/20 text-red-400 border-red-500/30'
                        }>
                          {testResults.test_results?.compiled ? 'Yes' : 'No'}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>Executed:</span>
                        <Badge variant="outline" className={
                          testResults.test_results?.executed 
                            ? 'bg-green-500/20 text-green-400 border-green-500/30' 
                            : 'bg-red-500/20 text-red-400 border-red-500/30'
                        }>
                          {testResults.test_results?.executed ? 'Yes' : 'No'}
                        </Badge>
                      </div>
                      {testResults.test_results?.execution_time && (
                        <div className="flex items-center gap-2">
                          <span>Execution Time:</span>
                          <span className="text-cyan-400">
                            {testResults.test_results.execution_time.toFixed(3)}s
                          </span>
                        </div>
                      )}
                      {testResults.test_results?.output && (
                        <details className="mt-2">
                          <summary className="cursor-pointer text-cyan-400 hover:text-cyan-300">
                            View Output
                          </summary>
                          <pre className="mt-2 p-2 bg-[#0f1729]/80 rounded text-xs overflow-x-auto">
                            {testResults.test_results.output}
                          </pre>
                        </details>
                      )}
                      {testResults.test_results?.error && (
                        <details className="mt-2">
                          <summary className="cursor-pointer text-red-400 hover:text-red-300">
                            View Errors
                          </summary>
                          <pre className="mt-2 p-2 bg-[#0f1729]/80 rounded text-xs overflow-x-auto text-red-300">
                            {testResults.test_results.error}
                          </pre>
                        </details>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
            <div className="flex justify-end">
              {vulnerability.status !== 'Patched' && (
                <Button className="bg-cyan-500 hover:bg-cyan-600 text-white" onClick={onApplyPatch}>
                  Apply Patch
                </Button>
              )}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
};

const StatCard = ({ title, value, icon: Icon, trend }: any) => (
  <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-4">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-sm text-gray-400">{title}</p>
        <h4 className="text-2xl font-bold text-gray-200 mt-1">{value}</h4>
        {trend && (
          <div className="flex items-center gap-1 mt-1">
            <ArrowUpRight className="w-4 h-4 text-green-500" />
            <span className="text-sm text-green-500">+{trend}%</span>
          </div>
        )}
      </div>
      <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
        <Icon className="w-5 h-5 text-cyan-400" />
      </div>
    </div>
  </Card>
);

const SEVERITY_COLORS = {
  Critical: "#ef4444",
  High: "#f59e42",
  Medium: "#facc15",
  Low: "#22d3ee"
};

const PatchManagement = () => {
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
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [trendData, setTrendData] = useState<{ timestamp: string, total: number }[]>([]);
  const [isApplyingAll, setIsApplyingAll] = useState(false);
  const [isGeneratingCompleteCode, setIsGeneratingCompleteCode] = useState(false);
  const [showCompleteCodeDialog, setShowCompleteCodeDialog] = useState(false);
  const [completePatchedCode, setCompletePatchedCode] = useState<string>('');
  const [copiedCompleteCode, setCopiedCompleteCode] = useState(false);
  const [isValidatingCompleteCode, setIsValidatingCompleteCode] = useState(false);
  const [dialogTestResults, setDialogTestResults] = useState<Vulnerability['testResults'] | null>(null);
  const codePreRef = useRef<HTMLPreElement>(null);

  const handleCopyCompleteCode = async () => {
    if (!completePatchedCode || completePatchedCode.trim() === '') {
      setError('No code available to copy');
      return;
    }

    try {
      // Use the same simple approach that works in VulnerabilityCard
      await navigator.clipboard.writeText(completePatchedCode);
      setCopiedCompleteCode(true);
      setError(null);
      setTimeout(() => {
        setCopiedCompleteCode(false);
      }, 2000);
    } catch (err) {
      console.error('Copy failed:', err);
      // Fallback: try textarea method
      try {
        const textArea = document.createElement('textarea');
        textArea.value = completePatchedCode;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '0';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);
        
        if (successful) {
          setCopiedCompleteCode(true);
          setError(null);
          setTimeout(() => {
            setCopiedCompleteCode(false);
          }, 2000);
        } else {
          setError('Failed to copy code. Please select and copy manually.');
        }
      } catch (fallbackErr) {
        console.error('Fallback copy failed:', fallbackErr);
        setError('Failed to copy. Please select the code manually and press Ctrl+C (or Cmd+C).');
      }
    }
  };

  const handleValidateCompletePatchedCode = async () => {
    if (!completePatchedCode || completePatchedCode.trim() === '') {
      setError('No complete code to validate. Generate code first.');
      return;
    }
    setIsValidatingCompleteCode(true);
    setError(null);
    setSuccess(null);
    try {
      const validateResponse = await fetch('http://127.0.0.1:8000/test-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_program_code: completePatchedCode,
          language: 'C++',
          vulnerability_type: '',
          vulnerable_code: '',
          timeout: 5,
          stdin: 'test-input\n'
        })
      });

      if (!validateResponse.ok) {
        const msg = await validateResponse.text();
        throw new Error(msg || 'Patch test service error');
      }

      const validateResult = await validateResponse.json();

      // Attach same validation result to all vulnerabilities
      setVulnerabilities(prev => {
        const updated = prev.map(v => ({ ...v, testResults: validateResult }));
        // also store for dialog display
        setDialogTestResults(validateResult);

        // Persist to localStorage
        const stored = localStorage.getItem('analysisResults');
        if (stored) {
          try {
            const parsed = JSON.parse(stored);
            parsed.vulnerabilities = updated;
            parsed.complete_fixed_code = completePatchedCode;
            localStorage.setItem('analysisResults', JSON.stringify(parsed));
          } catch (e) {
            console.error('Error saving validation results to localStorage:', e);
          }
        }

        return updated;
      });

      setSuccess(validateResult?.is_safe
        ? 'Validation passed for the complete patched code.'
        : 'Validation failed for the complete patched code. See details in each item.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to validate complete patched code');
    } finally {
      setIsValidatingCompleteCode(false);
    }
  };

  useEffect(() => {
    // Get vulnerabilities from localStorage
    const storedVulnerabilities = localStorage.getItem('analysisResults');
    const history = JSON.parse(localStorage.getItem('analysisHistory') || '[]');
    setTrendData(history);
    console.log('Retrieved from localStorage:', storedVulnerabilities); // Debug log

    if (storedVulnerabilities) {
      try {
        const parsedVulnerabilities = JSON.parse(storedVulnerabilities);
        console.log('Parsed vulnerabilities:', parsedVulnerabilities); // Debug log

        if (parsedVulnerabilities.vulnerabilities && Array.isArray(parsedVulnerabilities.vulnerabilities)) {
          // Load vulnerabilities with test results if they exist
          const loadedVulnerabilities = parsedVulnerabilities.vulnerabilities.map((v: Vulnerability) => ({
            ...v,
            // Preserve testResults if they exist
            testResults: v.testResults || undefined
          }));
          setVulnerabilities(loadedVulnerabilities);
          
          // Update statistics
          const newStats = {
            total: parsedVulnerabilities.vulnerabilities.length,
            patched: parsedVulnerabilities.vulnerabilities.filter((v: Vulnerability) => v.status === 'Patched').length,
            pending: parsedVulnerabilities.vulnerabilities.filter((v: Vulnerability) => v.status === 'Pending').length,
            inProgress: 0,
            severityDistribution: {
              Critical: 0,
              High: 0,
              Medium: 0,
              Low: 0
            }
          };

          // Count severity distribution
          parsedVulnerabilities.vulnerabilities.forEach((v: Vulnerability) => {
            const severity = v.severity.charAt(0).toUpperCase() + v.severity.slice(1);
            if (severity in newStats.severityDistribution) {
              newStats.severityDistribution[severity as keyof typeof newStats.severityDistribution]++;
            }
          });

          console.log('Updated statistics:', newStats); // Debug log
          setStatistics(newStats);
        } else {
          console.error('Invalid vulnerability data structure');
          setError('Invalid vulnerability data structure');
        }
      } catch (err) {
        console.error('Error parsing stored vulnerabilities:', err);
        setError('Failed to load vulnerability data');
      }
    } else {
      console.log('No vulnerabilities found in localStorage'); // Debug log
    }
    setIsLoading(false);
  }, [refreshTrigger]);

  const handleApplyPatch = async (vulnerabilityId: number) => {
    try {
      const vuln = vulnerabilities.find(v => v.id === vulnerabilityId);
      if (!vuln) return;

      // Get full code from localStorage
      const storedData = localStorage.getItem('analysisResults');
      let fullCode = '';
      if (storedData) {
        try {
          const analysisResults = JSON.parse(storedData);
          fullCode = analysisResults.userCode || '';
        } catch (err) {
          console.error('Error parsing stored data:', err);
        }
      }

      const response = await fetch('http://127.0.0.1:8000/generate-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: vuln.id,
          type: vuln.type,
          severity: vuln.severity,
          status: vuln.status,
          description: vuln.description,
          line: vuln.line,
          code: vuln.code,
          cwe_id: vuln.cwe_id,
          cwe_name: vuln.cwe_name,
          cwe_description: vuln.cwe_description,
          cwe_severity: vuln.cwe_severity,
          mitigation: vuln.mitigation,
          references: vuln.references,
          language: 'C++',
          full_code: fullCode  // Send complete original code
        })
      });

      if (!response.ok) {
        const msg = await response.text();
        throw new Error(msg || 'Patch service error');
      }

      const result = await response.json();

      // Merge returned patch data and complete fixed code into the selected vulnerability and mark as Patched
      setVulnerabilities(prev => {
        const updated = prev.map(v =>
          v.id === vulnerabilityId
            ? {
                ...v,
                status: 'Patched',
                patch: result?.patch || v.patch,
                complete_fixed_code: result?.complete_fixed_code || v.complete_fixed_code
              }
            : v
        );

        // Save updated vulnerabilities back to localStorage
        if (storedData) {
          try {
            const analysisResults = JSON.parse(storedData);
            analysisResults.vulnerabilities = updated;
            localStorage.setItem('analysisResults', JSON.stringify(analysisResults));
          } catch (err) {
            console.error('Error saving patches to localStorage:', err);
          }
        }

        return updated;
      });

      // Update statistics
      setStatistics(prev => ({
        ...prev,
        patched: prev.patched + 1,
        pending: Math.max(0, prev.pending - 1)
      }));

      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to apply patch');
      console.error('Error applying patch:', err);
    }
  };

  const handleApplyPatchToAll = async () => {
    setIsApplyingAll(true);
    setError(null);
    setSuccess(null);
    
    try {
      // Get all pending vulnerabilities, sorted by line number
      const pendingVulns = vulnerabilities
        .filter(v => v.status !== 'Patched')
        .sort((a, b) => (a.line || 0) - (b.line || 0));
      
      if (pendingVulns.length === 0) {
        setError('No pending vulnerabilities to patch');
        setIsApplyingAll(false);
        return;
      }

      // Get full code from localStorage
      const storedData = localStorage.getItem('analysisResults');
      if (!storedData) {
        throw new Error('No analysis results found');
      }

      const analysisResults = JSON.parse(storedData);
      let currentCode = analysisResults.userCode || '';
      
      if (!currentCode) {
        throw new Error('No original code found');
      }

      const updatedVulns = [...vulnerabilities];
      let finalCompleteCode = currentCode;
      let successCount = 0;
      let failureCount = 0;
      const errors: string[] = [];

      // Apply patches sequentially
      for (const vuln of pendingVulns) {
        try {
          const response = await fetch('http://127.0.0.1:8000/generate-patch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              id: vuln.id,
              type: vuln.type,
              severity: vuln.severity,
              status: vuln.status,
              description: vuln.description,
              line: vuln.line,
              code: vuln.code,
              cwe_id: vuln.cwe_id,
              cwe_name: vuln.cwe_name,
              cwe_description: vuln.cwe_description,
              cwe_severity: vuln.cwe_severity,
              mitigation: vuln.mitigation,
              references: vuln.references,
              language: 'C++',
              full_code: finalCompleteCode  // Use the current fixed code as base
            })
          });

          if (!response.ok) {
            const msg = await response.text();
            throw new Error(`Failed to patch vulnerability ${vuln.id}: ${msg || 'Patch service error'}`);
          }

          const result = await response.json();

          if (result.error) {
            throw new Error(`Error patching vulnerability ${vuln.id}: ${result.error}`);
          }

          // Update the vulnerability
          const vulnIndex = updatedVulns.findIndex(v => v.id === vuln.id);
          if (vulnIndex !== -1) {
            updatedVulns[vulnIndex] = {
              ...updatedVulns[vulnIndex],
              status: 'Patched',
              patch: result?.patch || updatedVulns[vulnIndex].patch,
              complete_fixed_code: result?.complete_fixed_code || updatedVulns[vulnIndex].complete_fixed_code
            };

            // Update the current code with the latest complete fixed code
            if (result?.complete_fixed_code) {
              finalCompleteCode = result.complete_fixed_code;
            }
            successCount++;
          }
        } catch (err) {
          console.error(`Error applying patch to vulnerability ${vuln.id}:`, err);
          failureCount++;
          const errorMsg = err instanceof Error ? err.message : `Failed to patch vulnerability ${vuln.id}`;
          errors.push(`Vulnerability ${vuln.id}: ${errorMsg}`);
        }
      }

      // Update all vulnerabilities and save to localStorage
      setVulnerabilities(updatedVulns);

      // Save updated vulnerabilities and complete fixed code to localStorage
      if (storedData) {
        try {
          const updatedAnalysisResults = JSON.parse(storedData);
          updatedAnalysisResults.vulnerabilities = updatedVulns;
          updatedAnalysisResults.complete_fixed_code = finalCompleteCode; // Store complete fixed code at root level
          localStorage.setItem('analysisResults', JSON.stringify(updatedAnalysisResults));
        } catch (err) {
          console.error('Error saving patches to localStorage:', err);
        }
      }

      // Update statistics
      const patchedCount = updatedVulns.filter(v => v.status === 'Patched').length;
      setStatistics(prev => ({
        ...prev,
        patched: patchedCount,
        pending: updatedVulns.length - patchedCount
      }));

      // Show success/error messages
      if (failureCount === 0) {
        setSuccess(`Successfully applied patches to all ${successCount} vulnerability/vulnerabilities!`);
        setError(null);
      } else if (successCount > 0) {
        setSuccess(`Successfully applied patches to ${successCount} vulnerability/vulnerabilities. ${failureCount} failed.`);
        setError(errors.join('; '));
      } else {
        setError(`Failed to apply patches. Errors: ${errors.join('; ')}`);
        setSuccess(null);
      }

      // Clear messages after 5 seconds
      setTimeout(() => {
        setSuccess(null);
        setError(null);
      }, 5000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to apply patches to all vulnerabilities');
      console.error('Error applying patches to all:', err);
    } finally {
      setIsApplyingAll(false);
    }
  };

  const handleGenerateCompletePatchedCode = async () => {
    setIsGeneratingCompleteCode(true);
    setError(null);
    setSuccess(null);
    
    try {
      // Get full code from localStorage
      const storedData = localStorage.getItem('analysisResults');
      if (!storedData) {
        throw new Error('No analysis results found');
      }

      const analysisResults = JSON.parse(storedData);
      let currentCode = analysisResults.userCode || '';
      
      if (!currentCode) {
        throw new Error('No original code found');
      }

      // Check if complete_fixed_code already exists in localStorage
      if (analysisResults.complete_fixed_code) {
        // Check if all vulnerabilities are patched
        const allPatched = vulnerabilities.every(v => v.status === 'Patched');
        if (allPatched) {
          setCompletePatchedCode(analysisResults.complete_fixed_code);
          setShowCompleteCodeDialog(true);
          setIsGeneratingCompleteCode(false);
          return;
        }
      }

      // Get all pending vulnerabilities, sorted by line number
      const pendingVulns = vulnerabilities
        .filter(v => v.status !== 'Patched')
        .sort((a, b) => (a.line || 0) - (b.line || 0));
      
      if (pendingVulns.length === 0) {
        // All vulnerabilities are already patched, use the stored complete code or last vulnerability's complete code
        const lastPatchedVuln = vulnerabilities
          .filter(v => v.status === 'Patched' && v.complete_fixed_code)
          .sort((a, b) => (b.line || 0) - (a.line || 0))[0];
        
        if (lastPatchedVuln?.complete_fixed_code) {
          setCompletePatchedCode(lastPatchedVuln.complete_fixed_code);
          setShowCompleteCodeDialog(true);
          setIsGeneratingCompleteCode(false);
          return;
        } else if (analysisResults.complete_fixed_code) {
          setCompletePatchedCode(analysisResults.complete_fixed_code);
          setShowCompleteCodeDialog(true);
          setIsGeneratingCompleteCode(false);
          return;
        } else {
          throw new Error('No patched code available. Please apply patches first.');
        }
      }

      const updatedVulns = [...vulnerabilities];

      // First, ensure all vulnerabilities have patches generated
      // Collect vulnerabilities that need patches
      const vulnsNeedingPatches = [];
      for (const vuln of pendingVulns) {
        // If patch is already available, use it; otherwise it will be generated by backend
        vulnsNeedingPatches.push({
          id: vuln.id,
          type: vuln.type,
          severity: vuln.severity,
          status: vuln.status,
          description: vuln.description,
          line: vuln.line,
          code: vuln.code,
          cwe_id: vuln.cwe_id,
          cwe_name: vuln.cwe_name,
          cwe_description: vuln.cwe_description,
          cwe_severity: vuln.cwe_severity,
          mitigation: vuln.mitigation,
          references: vuln.references,
          patch_code: vuln.patch?.code || null  // Use existing patch if available
        });
      }

      // Apply ALL patches at once using the new endpoint (more accurate)
      let finalCompleteCode = currentCode;
      try {
        const response = await fetch('http://127.0.0.1:8000/generate-complete-code-multiple', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            full_code: currentCode,
            language: 'C++',
            vulnerabilities: vulnsNeedingPatches
          })
        });

        if (!response.ok) {
          const msg = await response.text();
          throw new Error(`Failed to generate complete patched code: ${msg || 'Patch service error'}`);
        }

        const result = await response.json();

        if (result.error) {
          throw new Error(`Error generating complete code: ${result.error}`);
        }

        if (result.complete_fixed_code) {
          finalCompleteCode = result.complete_fixed_code;
          
          // Update all vulnerabilities to Patched status
          for (const vuln of pendingVulns) {
            const vulnIndex = updatedVulns.findIndex(v => v.id === vuln.id);
            if (vulnIndex !== -1) {
              updatedVulns[vulnIndex] = {
                ...updatedVulns[vulnIndex],
                status: 'Patched',
                complete_fixed_code: finalCompleteCode
              };
            }
          }
        } else {
          throw new Error('No complete fixed code returned from server');
        }
      } catch (err) {
        console.error('Error generating complete patched code:', err);
        throw err;  // Re-throw to show error to user
      }

      // Update vulnerabilities in state and localStorage
      setVulnerabilities(updatedVulns);

      // Save updated vulnerabilities and complete fixed code to localStorage
      if (storedData) {
        try {
          const updatedAnalysisResults = JSON.parse(storedData);
          updatedAnalysisResults.vulnerabilities = updatedVulns;
          updatedAnalysisResults.complete_fixed_code = finalCompleteCode;
          localStorage.setItem('analysisResults', JSON.stringify(updatedAnalysisResults));
        } catch (err) {
          console.error('Error saving complete code to localStorage:', err);
        }
      }

      // Update statistics
      const patchedCount = updatedVulns.filter(v => v.status === 'Patched').length;
      setStatistics(prev => ({
        ...prev,
        patched: patchedCount,
        pending: updatedVulns.length - patchedCount
      }));

      // After generating the complete code, automatically validate it once
      try {
        const validateResponse = await fetch('http://127.0.0.1:8000/test-patch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            full_program_code: finalCompleteCode,
            language: 'C++',
            vulnerability_type: '',
            vulnerable_code: '',
            timeout: 5,
            stdin: 'test-input\n'
          })
        });

        if (validateResponse.ok) {
          const validateResult = await validateResponse.json();

          // Attach the shared validation result to all vulnerabilities
          setVulnerabilities(prev => {
            const withResults = prev.map(v => ({ ...v, testResults: validateResult }));

            // Persist to localStorage
            const stored = localStorage.getItem('analysisResults');
            if (stored) {
              try {
                const parsed = JSON.parse(stored);
                parsed.vulnerabilities = withResults;
                parsed.complete_fixed_code = finalCompleteCode;
                localStorage.setItem('analysisResults', JSON.stringify(parsed));
              } catch (e) {
                console.error('Error saving validation results to localStorage:', e);
              }
            }

            return withResults;
          });

          // Inform the user about validation outcome
          setSuccess(validateResult?.is_safe
            ? 'Generated and validated complete patched code: runtime tests passed.'
            : 'Generated complete patched code, but validation failed. See results in each item.');
        } else {
          // If validation API fails, still show the code dialog
          const msg = await validateResponse.text();
          console.warn('Bulk validation failed:', msg);
          setSuccess('Generated complete patched code. Validation service unavailable.');
        }
      } catch (e) {
        console.warn('Bulk validation error:', e);
        setSuccess('Generated complete patched code. Validation encountered an error.');
      }

      // Set the complete code and show dialog
      setCompletePatchedCode(finalCompleteCode);
      setShowCompleteCodeDialog(true);
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        setSuccess(null);
      }, 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate complete patched code');
      console.error('Error generating complete patched code:', err);
    } finally {
      setIsGeneratingCompleteCode(false);
    }
  };

  const handleTestPatch = async (vulnerabilityId: number) => {
    try {
      const vuln = vulnerabilities.find(v => v.id === vulnerabilityId);
      if (!vuln || !vuln.patch) {
        setError('No patch available to test');
        return;
      }

      const response = await fetch('http://127.0.0.1:8000/test-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          // Prefer testing the complete fixed program when available
          full_program_code: vuln.complete_fixed_code || undefined,
          patch_code: !vuln.complete_fixed_code ? vuln.patch.code : undefined,
          language: 'C++',
          vulnerability_type: vuln.type || vuln.cwe_id || '',
          vulnerable_code: vuln.code || '',
          timeout: 5,
          // Provide safe default input to avoid blocking on fgets/scanf
          stdin: 'test-input\n'
        })
      });

      if (!response.ok) {
        const msg = await response.text();
        throw new Error(msg || 'Patch test service error');
      }

      const result = await response.json();

      // Update vulnerability with test results
      setVulnerabilities(prev => {
        const updated = prev.map(v =>
          v.id === vulnerabilityId
            ? { ...v, testResults: result }
            : v
        );

        // Save updated vulnerabilities back to localStorage
        const storedData = localStorage.getItem('analysisResults');
        if (storedData) {
          try {
            const analysisResults = JSON.parse(storedData);
            analysisResults.vulnerabilities = updated;
            localStorage.setItem('analysisResults', JSON.stringify(analysisResults));
          } catch (err) {
            console.error('Error saving test results to localStorage:', err);
          }
        }

        return updated;
      });

      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to test patch');
      console.error('Error testing patch:', err);
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter(v => 
    selectedSeverity === 'all' || v.severity.toLowerCase() === selectedSeverity.toLowerCase()
  );

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
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                    <ShieldCheck className="text-cyan-400" size={24} />
                  </div>
                  <div>
                    <h1 className="text-2xl font-bold text-cyan-500">Patch Management</h1>
                    <p className="text-gray-400 mt-1">Monitor and manage security vulnerabilities</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <ScrollArea className="flex-1">
            <div className="max-w-7xl mx-auto p-6 space-y-6">
              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5" />
                    <span>{error}</span>
                  </div>
                </div>
              )}
              {success && (
                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 text-green-400">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5" />
                    <span>{success}</span>
                  </div>
                </div>
              )}

              {/* Statistics */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                  title="Total Vulnerabilities"
                  value={statistics.total}
                  icon={AlertTriangle}
                  trend={12}
                />
                <StatCard
                  title="Patched"
                  value={statistics.patched}
                  icon={ShieldCheck}
                  trend={8}
                />
                <StatCard
                  title="Pending"
                  value={statistics.pending}
                  icon={Clock}
                />
                <StatCard
                  title="In Progress"
                  value={statistics.inProgress}
                  icon={Activity}
                />
              </div>

              {/* Graphs Section */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-200">Vulnerability Trends</h3>
                    <Button variant="ghost" size="sm" className="text-cyan-400 hover:text-cyan-300">
                      <BarChart3 className="w-4 h-4" />
                    </Button>
                  </div>
                  <div className="h-[200px] flex items-center justify-center text-gray-400">
                    <ReResponsiveContainer width="100%" height={200}>
                      <ReLineChart data={trendData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" tickFormatter={t => new Date(t).toLocaleDateString()} />
                        <YAxis allowDecimals={false} />
                        <ReTooltip />
                        <Line type="monotone" dataKey="total" stroke="#06b6d4" strokeWidth={2} />
                      </ReLineChart>
                    </ReResponsiveContainer>
                  </div>
                </Card>

                <Card className="bg-[#1a2234]/50 border border-cyan-500/10 backdrop-blur-sm p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-200">Severity Distribution</h3>
                    <Button variant="ghost" size="sm" className="text-cyan-400 hover:text-cyan-300">
                      <PieChart className="w-4 h-4" />
                    </Button>
                  </div>
                  <div className="h-[200px] flex items-center justify-center text-gray-400">
                    <ReResponsiveContainer width="100%" height={200}>
                      <RePieChart>
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
                        <ReTooltip />
                        <ReLegend />
                      </RePieChart>
                    </ReResponsiveContainer>
                  </div>
                </Card>
              </div>

              {/* Latest Complete Code Validation */}
              {dialogTestResults && (
                <div className={`rounded-lg border p-4 ${
                  dialogTestResults.is_safe 
                    ? 'border-green-500/20 bg-green-500/10' 
                    : 'border-red-500/20 bg-red-500/10'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {dialogTestResults.is_safe ? (
                        <CheckCircle2 className="w-5 h-5 text-green-400" />
                      ) : (
                        <XCircle className="w-5 h-5 text-red-400" />
                      )}
                      <h3 className="text-sm font-semibold text-gray-200">
                        Runtime Test Results (Complete Patched Code)
                      </h3>
                    </div>
                  </div>
                  <p className={`mt-2 text-sm ${
                    dialogTestResults.is_safe ? 'text-green-300' : 'text-red-300'
                  }`}>
                    {dialogTestResults.message}
                  </p>
                  <div className="mt-2 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs text-gray-300">
                    <div className="flex items-center gap-2">
                      <span>Compiled:</span>
                      <Badge variant="outline" className={
                        dialogTestResults.test_results?.compiled 
                          ? 'bg-green-500/20 text-green-400 border-green-500/30' 
                          : 'bg-red-500/20 text-red-400 border-red-500/30'
                      }>
                        {dialogTestResults.test_results?.compiled ? 'Yes' : 'No'}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      <span>Executed:</span>
                      <Badge variant="outline" className={
                        dialogTestResults.test_results?.executed 
                          ? 'bg-green-500/20 text-green-400 border-green-500/30' 
                          : 'bg-red-500/20 text-red-400 border-red-500/30'
                      }>
                        {dialogTestResults.test_results?.executed ? 'Yes' : 'No'}
                      </Badge>
                    </div>
                    {dialogTestResults.test_results?.execution_time && (
                      <div className="flex items-center gap-2">
                        <span>Execution Time:</span>
                        <span className="text-cyan-400">
                          {dialogTestResults.test_results.execution_time.toFixed(3)}s
                        </span>
                      </div>
                    )}
                  </div>
                  <div className="mt-2">
                    {dialogTestResults.test_results?.output && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-cyan-400 hover:text-cyan-300">
                          View Output
                        </summary>
                        <pre className="mt-2 p-2 bg-[#0f1729]/80 rounded text-xs overflow-x-auto">
                          {dialogTestResults.test_results.output}
                        </pre>
                      </details>
                    )}
                    {dialogTestResults.test_results?.error && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-red-400 hover:text-red-300">
                          View Errors
                        </summary>
                        <pre className="mt-2 p-2 bg-[#0f1729]/80 rounded text-xs overflow-x-auto text-red-300">
                          {dialogTestResults.test_results.error}
                        </pre>
                      </details>
                    )}
                  </div>
                </div>
              )}

              {/* Vulnerabilities List */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-gray-200">Detected Vulnerabilities</h2>
                  <div className="flex items-center gap-4">
                    {vulnerabilities.filter(v => v.status !== 'Patched').length > 0 && (
                      <Button
                        className="bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white border-0"
                        onClick={handleApplyPatchToAll}
                        disabled={isApplyingAll}
                      >
                        {isApplyingAll ? (
                          <>
                            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                            Applying Patches...
                          </>
                        ) : (
                          <>
                            <Zap className="w-4 h-4 mr-2" />
                            Apply Patch to All ({vulnerabilities.filter(v => v.status !== 'Patched').length})
                          </>
                        )}
                      </Button>
                    )}
                    {vulnerabilities.length > 0 && (
                      <Button
                        className="bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white border-0"
                        onClick={handleGenerateCompletePatchedCode}
                        disabled={isGeneratingCompleteCode}
                      >
                        {isGeneratingCompleteCode ? (
                          <>
                            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                            Generating Code...
                          </>
                        ) : (
                          <>
                            <FileCode className="w-4 h-4 mr-2" />
                            Generate Complete Patched Code
                          </>
                        )}
                      </Button>
                    )}
                    <Tabs 
                      defaultValue="all" 
                      className="w-[400px]"
                      onValueChange={setSelectedSeverity}
                    >
                      <TabsList className="bg-[#1a2234]/50 border border-cyan-500/10">
                        <TabsTrigger value="all" className="data-[state=active]:bg-cyan-500">All</TabsTrigger>
                        <TabsTrigger value="critical" className="data-[state=active]:bg-cyan-500">Critical</TabsTrigger>
                        <TabsTrigger value="high" className="data-[state=active]:bg-cyan-500">High</TabsTrigger>
                        <TabsTrigger value="medium" className="data-[state=active]:bg-cyan-500">Medium</TabsTrigger>
                      </TabsList>
                    </Tabs>
                  </div>
                </div>

                {isLoading ? (
                  <div className="flex items-center justify-center p-8">
                    <div className="animate-spin">
                      <Activity className="w-8 h-8 text-cyan-400" />
                    </div>
                    <span className="ml-2 text-cyan-400">Loading vulnerabilities...</span>
                  </div>
                ) : filteredVulnerabilities.length === 0 ? (
                  <div className="text-center p-8 text-gray-400">
                    No vulnerabilities found
                  </div>
                ) : (
                  <div className="space-y-4">
                    {filteredVulnerabilities.map((vulnerability) => (
                      <VulnerabilityCard 
                        key={vulnerability.id} 
                        vulnerability={vulnerability}
                        onApplyPatch={() => handleApplyPatch(vulnerability.id)}
                        onTestPatch={handleTestPatch}
                      />
                    ))}
                  </div>
                )}
              </div>
            </div>
          </ScrollArea>
        </main>
      </div>

      {/* Complete Patched Code Dialog */}
      <Dialog open={showCompleteCodeDialog} onOpenChange={setShowCompleteCodeDialog}>
        <DialogContent className="max-w-4xl max-h-[90vh] bg-[#1a2234] border-cyan-500/20">
          <DialogHeader>
            <DialogTitle className="text-cyan-400 text-xl">Complete Patched Code</DialogTitle>
            <DialogDescription className="text-gray-400">
              This is the complete vulnerability-free code with all patches applied. You can copy it to use in your project.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="rounded-lg border border-cyan-500/20 bg-[#0f1729]/80 p-4 relative">
              <div className="absolute top-2 right-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="bg-cyan-500 text-white border-cyan-500 hover:bg-cyan-600 hover:border-cyan-600 hover:text-white"
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    const codeToCopy = completePatchedCode || '';
                    if (!codeToCopy || codeToCopy.trim() === '') {
                      setError('No code available to copy');
                      console.error('No code to copy');
                      return;
                    }
                    
                    console.log('Attempting to copy code, length:', codeToCopy.length);
                    
                    // Use the EXACT same pattern that works in VulnerabilityCard
                    try {
                      navigator.clipboard.writeText(codeToCopy);
                      setCopiedCompleteCode(true);
                      setError(null);
                      setTimeout(() => {
                        setCopiedCompleteCode(false);
                      }, 2000);
                    } catch (err) {
                      console.error('Copy error:', err);
                      // Fallback: use textarea
                      const textArea = document.createElement('textarea');
                      textArea.value = codeToCopy;
                      textArea.style.position = 'fixed';
                      textArea.style.left = '-999999px';
                      document.body.appendChild(textArea);
                      textArea.select();
                      document.execCommand('copy');
                      document.body.removeChild(textArea);
                      setCopiedCompleteCode(true);
                      setError(null);
                      setTimeout(() => {
                        setCopiedCompleteCode(false);
                      }, 2000);
                    }
                  }}
                >
                  {copiedCompleteCode ? (
                    <>
                      <Check className="w-4 h-4 mr-1" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4 mr-1" />
                      Copy Code
                    </>
                  )}
                </Button>
              </div>
              <ScrollArea className="h-[60vh] pr-4">
                <pre 
                  ref={codePreRef}
                  className="text-sm text-cyan-300 whitespace-pre-wrap font-mono overflow-x-auto"
                >
                  {completePatchedCode}
                </pre>
              </ScrollArea>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={handleValidateCompletePatchedCode}
              disabled={!completePatchedCode || isValidatingCompleteCode}
              className="bg-emerald-500 text-white border-emerald-500 hover:bg-emerald-600 hover:border-emerald-600 hover:text-white"
            >
              {isValidatingCompleteCode ? (
                <>
                  <Loader2 className="w-4 h-4 mr-1 animate-spin" />
                  Validating...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 mr-1" />
                  Validate Patch
                </>
              )}
            </Button>
            <Button
              variant="outline"
              onClick={() => setShowCompleteCodeDialog(false)}
              className="bg-cyan-500 text-white border-cyan-500 hover:bg-cyan-600 hover:border-cyan-600 hover:text-white"
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </SidebarProvider>
  );
};

export default PatchManagement; 