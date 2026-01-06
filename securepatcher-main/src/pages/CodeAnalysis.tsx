import React, { useState } from 'react';
import { SidebarProvider } from "@/components/ui/sidebar";
import DashboardSidebar from "@/components/DashboardSidebar";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Zap, Send, Code, AlertTriangle, FileCode, Shield, Lock, Badge } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { LineChart, Line, XAxis, YAxis, CartesianGrid } from 'recharts';


interface Message {
  type: 'user' | 'assistant';
  content: string;
  code?: string;
  cwe?: string;
  vulnerabilities?: Vulnerability[];
}

interface CodeSubmission {
  id: string;
  code: string;
  timestamp: Date;
  vulnerabilities?: string[];
}

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
  // Add appropriate properties for statistics
}

// Helper function for C/C++ code check
function isCOrCppCode(code: string) {
  // Patterns that strongly indicate C or C++
  const cOrCppPatterns = [
    /#include\s*<[^>]+>/, // C/C++ include
    /\bint\s+main\s*\(/, // main function
    /\bprintf\s*\(/, // printf
    /\bscanf\s*\(/, // scanf
    /std::\w+/, // C++ std namespace
    /using\s+namespace\s+std;/, // C++ using namespace
    /\bcout\s*<</, // C++ cout
    /\bcin\s*>>/, // C++ cin
    /\bclass\s+\w+/, // C++ class
    /\/\//, // C/C++ single-line comment
    /\/\*[\s\S]*?\*\//, // C/C++ multi-line comment
    /;\s*$/m // line ends with semicolon
  ];

  // Patterns that indicate other languages (explicitly reject)
  const forbiddenPatterns = [
    /def\s+\w+\s*\(/, // Python
    /console\.log\s*\(/, // JavaScript
    /function\s+\w+\s*\(/, // JavaScript
    /public\s+class\s+\w+/, // Java
    /System\.out\.println\s*\(/, // Java
    /fn\s+main\s*\(/, // Rust
    /println!\s*\(/, // Rust
    /<\?php/, // PHP
    /echo\s+['"]/ // PHP
  ];

  // If any forbidden pattern matches, reject
  if (forbiddenPatterns.some(pattern => pattern.test(code))) {
    return false;
  }
  // Require at least two C/C++ patterns to match for confidence
  const matches = cOrCppPatterns.filter(pattern => pattern.test(code));
  return matches.length >= 2;
}

// Additional sanitization helpers
function hasMinimumLength(code: string, minLength = 20) {
  return code.replace(/\s/g, '').length >= minLength;
}

function hasBalancedBracesAndParens(code: string) {
  const stack: string[] = [];
  const pairs: Record<string, string> = { '}': '{', ')': '(' };
  for (const char of code) {
    if (char === '{' || char === '(') stack.push(char);
    if (char === '}' || char === ')') {
      if (stack.pop() !== pairs[char]) return false;
    }
  }
  return stack.length === 0;
}

function containsHTMLorScript(code: string) {
  return /<script|<html|<body|<div|<span|<head|<title|<style/i.test(code);
}

function containsDangerousFunctions(code: string) {
  // List of some dangerous C/C++ functions
  const dangerous = [/\bgets\b/, /\bstrcpy\b/, /\bsprintf\b/, /\bscanf\b/];
  return dangerous.some(pattern => pattern.test(code));
}

// Helper to escape HTML special characters
function escapeHtml(text: string) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getAuthToken() {
  const sessionStr = localStorage.getItem('session');
  if (!sessionStr) return null;
  try {
    const session = JSON.parse(sessionStr);
    return session?.token || null;
  } catch {
    return null;
  }
}

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-400';
    case 'medium': return 'text-yellow-300';
    case 'low': return 'text-green-400';
    default: return 'text-gray-300';
  }
}

const SEVERITY_COLORS = {
  Critical: "#ef4444",
  High: "#f59e42",
  Medium: "#facc15",
  Low: "#22d3ee"
};

const CodeAnalysis = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputCode, setInputCode] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [codeError, setCodeError] = useState<string | null>(null);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);

  const handleSubmit = async () => {
    let hasError = false;
    setCodeError(null);
    setSaveStatus(null);

    if (!inputCode.trim()) {
      setCodeError('Code input cannot be empty.');
      hasError = true;
    } else if (!isCOrCppCode(inputCode)) {
      setCodeError('No C/C++ code detected. Please paste valid C or C++ code.');
      hasError = true;
    } else if (!hasMinimumLength(inputCode)) {
      setCodeError('Code is too short. Please provide a more complete C or C++ code sample.');
      hasError = true;
    } else if (!hasBalancedBracesAndParens(inputCode)) {
      setCodeError('Unbalanced braces or parentheses detected. Please check your code.');
      hasError = true;
    } else if (containsHTMLorScript(inputCode)) {
      setCodeError('HTML or script tags detected. Only C/C++ code is allowed.');
      hasError = true;
    }
    if (hasError) return;

    const userMessage: Message = {
      type: 'user',
      content: '<span class="text-cyan-400">Please analyze this code:</span>',
      code: inputCode
    };

    setMessages(prev => [...prev, userMessage]);
    setIsAnalyzing(true);
    setSaveStatus(null);

    try {
      const response = await fetch('http://localhost:3001/api/analyze-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: inputCode })
      });
      const data = await response.json();
      if (!response.ok) {
        setSaveStatus('Analysis failed: ' + (data.error || 'Unknown error'));
      } else {
        // Store the analysis results in localStorage
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
          const vulnerabilitiesWithIds = data.vulnerabilities.map((v: Vulnerability, index: number) => ({
            ...v,
            id: index + 1,
            status: 'Pending'
          }));

          const analysisResults = {
            vulnerabilities: vulnerabilitiesWithIds,
            timestamp: new Date().toISOString(),
            userCode: inputCode  // Store the user's code for PDF reports
          };

          localStorage.setItem('analysisResults', JSON.stringify(analysisResults));
          console.log('Stored vulnerabilities:', analysisResults); // Debug log

          let history = JSON.parse(localStorage.getItem('analysisHistory') || '[]');
          history.push({ timestamp: new Date().toISOString(), total: vulnerabilitiesWithIds.length });
          localStorage.setItem('analysisHistory', JSON.stringify(history));
        }

        setMessages(prev => [
          ...prev,
          {
            type: 'assistant',
            content: data.vulnerabilities.length > 0
              ? `${data.vulnerabilities.length} vulnerabilities found`
              : `No vulnerabilities detected in ${data.language} code.`,
            vulnerabilities: data.vulnerabilities.length > 0 ? data.vulnerabilities : undefined
          }
        ]);
        setSaveStatus('Analysis complete.');
      }
    } catch (err) {
      setSaveStatus('Failed to analyze code: ' + (err instanceof Error ? err.message : 'Unknown error'));
    }
    setIsAnalyzing(false);
    setInputCode('');
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
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                    <Code className="text-cyan-400" size={24} />
                  </div>
                  <div>
                    <h1 className="text-2xl font-bold text-cyan-500">Code Analysis</h1>
                    <p className="text-gray-400 mt-1">Analyze your code for security vulnerabilities</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Chat Area */}
          <ScrollArea className="flex-1 p-4">
            <div className="max-w-4xl mx-auto space-y-6">
              {messages.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-[calc(100vh-300px)] text-center space-y-6">
                  <div className="relative">
                    <div className="absolute inset-0 bg-cyan-500 rounded-full blur-xl opacity-20 animate-pulse"></div>
                    <div className="relative p-4 rounded-full bg-cyan-500/20 border border-cyan-500/30">
                      <Shield className="text-cyan-400 w-12 h-12" />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <h2 className="text-2xl font-semibold text-white">Start Your Security Analysis</h2>
                    <p className="text-gray-400 max-w-md">
                      Enter your code and specify CWE (Common Weakness Enumeration) for targeted vulnerability assessment and patches
                    </p>
                  </div>
                </div>
              ) : (
                messages.map((message, index) => (
                  <Card 
                    key={index} 
                    className={`
                      relative p-4 border-0 overflow-hidden
                      ${message.type === 'assistant' 
                        ? 'bg-gradient-to-r from-[#1a2234]/90 to-[#1a2234]/50 backdrop-blur-sm' 
                        : 'bg-gradient-to-r from-[#1a2234]/70 to-[#1a2234]/40 backdrop-blur-sm'}
                    `}
                  >
                    <div className="absolute inset-0 border border-cyan-500/10 rounded-lg"></div>
                    <div className="relative flex items-start gap-3">
                      {message.type === 'assistant' ? (
                        <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center">
                          <Zap className="text-cyan-400" size={16} />
                        </div>
                      ) : (
                        <div className="w-8 h-8 rounded-lg bg-slate-700/30 border border-slate-600/30 flex items-center justify-center">
                          <FileCode className="text-slate-300" size={16} />
                        </div>
                      )}
                      <div className="flex-1 space-y-2">
                        {message.vulnerabilities ? (
                          <>
                            <div className="font-bold text-cyan-300 mb-4 text-lg flex items-center gap-2">
                              <Zap className="inline-block text-cyan-400" size={20} />
                              {message.vulnerabilities.length} vulnerabilities found:
                            </div>
                            <ul className="space-y-8 mt-2">
                              {message.vulnerabilities.map((v, i) => (
                                <li key={i} className="p-6 rounded-xl bg-slate-900 border-2 border-cyan-700/40 shadow-lg relative">
                                  <div className={`font-bold text-lg flex items-center gap-2 ${getSeverityColor(v.severity).split(' ')[0]}`}>
                                    <AlertTriangle className="w-5 h-5" />
                                    {v.type}
                                    <div className={`px-2 py-0.5 text-xs rounded-full border ${getSeverityColor(v.severity)}`}>
                                      {v.severity}
                                    </div>
                                  </div>
                                  
                                  <div className="mt-4 space-y-4">
                                    <div className="space-y-2">
                                      <h4 className="text-sm font-medium text-gray-300">Vulnerability Details</h4>
                                      <div className="rounded-lg border border-cyan-500/10 bg-[#0f1729]/80 p-3 space-y-1">
                                        {v.line && <div className="text-xs text-cyan-400 font-mono">Line {v.line}: <span className="text-white">{v.code}</span></div>}
                                        <div className="text-base text-gray-200 mt-1">{v.description}</div>
                                      </div>
                                    </div>

                                    <div className="p-4 rounded-lg bg-cyan-950/60 border border-cyan-700/30">
                                      <div className="flex items-center gap-2 mb-2">
                                        <Shield className="text-cyan-400" size={16} />
                                        <span className="font-semibold text-cyan-300">CWE Information</span>
                                      </div>
                                      <div className="text-xs text-cyan-400 mb-1">
                                        <strong>CWE:</strong> <span className="font-bold">{v.cwe_id}</span> - <span className="font-semibold">{v.cwe_name}</span>
                                      </div>
                                      <div className="text-xs text-gray-300 mb-2">{v.cwe_description}</div>
                                      <div className="text-xs text-cyan-300 mb-1"><strong>CWE Severity:</strong> <span className="font-semibold">{v.cwe_severity}</span></div>
                                      <div className="text-xs text-cyan-300 mb-1 flex items-center gap-1">
                                        <Lock className="inline-block text-cyan-400" size={13} />
                                        <strong>Mitigation:</strong>
                                      </div>
                                      <ul className="list-disc list-inside ml-4 mb-2 text-xs text-gray-200">
                                        {v.mitigation && v.mitigation.map((m: string, idx: number) => <li key={idx}>{m}</li>)}
                                      </ul>
                                      {v.references && v.references.length > 0 && (
                                        <div className="text-xs text-cyan-300 mt-2">
                                          <strong>References:</strong>
                                          <ul className="list-disc list-inside ml-4">
                                            {v.references.map((ref: string, idx: number) => (
                                              <li key={idx}><a href={ref} target="_blank" rel="noopener noreferrer" className="underline text-cyan-400 hover:text-cyan-200">{ref}</a></li>
                                            ))}
                                          </ul>
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          </>
                        ) : (
                          <p className="text-sm" dangerouslySetInnerHTML={{ __html: message.content }} />
                        )}
                        {message.code && (
                          <div className="relative mt-2 group">
                            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 to-transparent rounded-lg"></div>
                            <div className="relative bg-[#0f1729]/80 rounded-lg p-4 font-mono text-sm text-gray-300 overflow-x-auto border border-cyan-500/10" dangerouslySetInnerHTML={{ __html: escapeHtml(message.code) }} />
                          </div>
                        )}
                      </div>
                    </div>
                  </Card>
                ))
              )}
              {isAnalyzing && (
                <Card className="relative p-4 bg-gradient-to-r from-[#1a2234]/90 to-[#1a2234]/50 border-0 overflow-hidden backdrop-blur-sm">
                  <div className="absolute inset-0 border border-cyan-500/10 rounded-lg"></div>
                  <div className="relative flex items-center gap-2 text-cyan-400">
                    <div className="animate-spin">
                      <Zap size={16} />
                    </div>
                    <span>Analyzing code...</span>
                  </div>
                </Card>
              )}
            </div>
          </ScrollArea>

          {/* Input Area */}
          <div className="relative flex-none border-t border-cyan-500/10">
            <div className="absolute inset-0 bg-gradient-to-t from-[#1a2234]/80 to-[#1a2234]/30 backdrop-blur-sm"></div>
            <div className="relative p-4">
              <div className="max-w-4xl mx-auto space-y-4">
                <div className="grid grid-cols-4 gap-4">
                  <div className="col-span-3">
                    <Textarea
                      value={inputCode}
                      onChange={(e) => setInputCode(e.target.value)}
                      placeholder="Enter your code here..."
                      className={`
                        min-h-[120px] bg-[#0f1729]/80 border-0
                        ${codeError ? 'border-red-500' : 'border-cyan-500/20'}
                        text-gray-100 resize-none rounded-lg
                        focus:border-cyan-500/50 focus:ring-cyan-500/20 placeholder-gray-500
                        transition-colors duration-200
                      `}
                    />
                    {codeError && <div className="text-red-400 text-xs mt-1">{codeError}</div>}
                    {saveStatus && <div className={`text-xs mt-1 ${saveStatus.startsWith('Code saved') ? 'text-green-400' : 'text-red-400'}`}>{saveStatus}</div>}
                  </div>
                  <div className="col-span-1 space-y-4">
                    <Button
                      onClick={handleSubmit}
                      disabled={isAnalyzing || !inputCode.trim()}
                      className={`
                        w-full relative group overflow-hidden rounded-lg
                        ${isAnalyzing || !inputCode.trim()
                          ? 'bg-cyan-500/50 cursor-not-allowed'
                          : 'bg-cyan-500 hover:bg-cyan-600 hover:shadow-lg hover:shadow-cyan-500/20'}
                        transition-all duration-200
                      `}
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent opacity-0 group-hover:opacity-100 group-hover:translate-x-full duration-700 transition-all"></div>
                      {isAnalyzing ? (
                        <span className="flex items-center gap-2">
                          <div className="animate-spin">
                            <Zap size={16} />
                          </div>
                          Analyzing...
                        </span>
                      ) : (
                        <span className="flex items-center gap-2">
                          <Send size={16} />
                          Analyze
                        </span>
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </SidebarProvider>
  );
};

export default CodeAnalysis;