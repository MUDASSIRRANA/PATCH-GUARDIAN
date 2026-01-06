import jsPDF from 'jspdf';

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
  complete_fixed_code?: string;
}

interface AnalysisResults {
  vulnerabilities: Vulnerability[];
  timestamp: string;
  userCode?: string;
  complete_fixed_code?: string;
}

export const generatePDFReport = () => {
  // Get data from localStorage
  const storedData = localStorage.getItem('analysisResults');
  if (!storedData) {
    throw new Error('No analysis results found. Please analyze code first.');
  }

  const analysisResults: AnalysisResults = JSON.parse(storedData);
  const { vulnerabilities, timestamp, userCode, complete_fixed_code } = analysisResults;

  if (!vulnerabilities || vulnerabilities.length === 0) {
    throw new Error('No vulnerabilities found to include in report.');
  }

  // Create PDF
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  let yPosition = margin;

  // Helper function to add new page if needed
  const checkPageBreak = (requiredHeight: number = 10) => {
    if (yPosition + requiredHeight > pageHeight - margin) {
      doc.addPage();
      yPosition = margin;
      return true;
    }
    return false;
  };

  // Helper function to add text with word wrap
  const addText = (text: string, fontSize: number = 10, fontStyle: string = 'normal', color: number[] = [0, 0, 0], maxWidth?: number) => {
    if (!text || text.trim() === '') return 0;
    
    doc.setFontSize(fontSize);
    doc.setFont('helvetica', fontStyle);
    doc.setTextColor(color[0], color[1], color[2]);
    
    const textWidth = maxWidth || (pageWidth - 2 * margin);
    const lines = doc.splitTextToSize(String(text), textWidth);
    
    lines.forEach((line: string) => {
      checkPageBreak(fontSize * 0.6);
      doc.text(line, margin, yPosition);
      yPosition += fontSize * 0.5;
    });
    
    return lines.length * fontSize * 0.5;
  };

  // Title
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(6, 182, 212); // Cyan color
  doc.text('SecurePatcher Vulnerability Report', pageWidth / 2, yPosition, { align: 'center' });
  yPosition += 10;

  // Report Date
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 100, 100);
  const reportDate = new Date(timestamp).toLocaleString();
  doc.text(`Generated: ${reportDate}`, pageWidth / 2, yPosition, { align: 'center' });
  yPosition += 10;

  // Summary Section
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('Executive Summary', margin, yPosition);
  yPosition += 8;

  const totalVulns = vulnerabilities.length;
  const patchedCount = vulnerabilities.filter(v => v.status === 'Patched').length;
  const pendingCount = vulnerabilities.filter(v => v.status === 'Pending').length;
  const criticalCount = vulnerabilities.filter(v => v.severity === 'Critical').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
  const mediumCount = vulnerabilities.filter(v => v.severity === 'Medium').length;
  const lowCount = vulnerabilities.filter(v => v.severity === 'Low').length;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  yPosition += addText(`Total Vulnerabilities: ${totalVulns}`, 10, 'normal', [0, 0, 0]);
  yPosition += addText(`Patched: ${patchedCount} | Pending: ${pendingCount}`, 10, 'normal', [0, 0, 0]);
  yPosition += addText(`Severity Breakdown: Critical: ${criticalCount}, High: ${highCount}, Medium: ${mediumCount}, Low: ${lowCount}`, 10, 'normal', [0, 0, 0]);
  yPosition += 8;

  // User Code Section
  if (userCode) {
    checkPageBreak(20);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Analyzed Code', margin, yPosition);
    yPosition += 8;

    doc.setFontSize(9);
    doc.setFont('courier', 'normal');
    doc.setTextColor(0, 0, 0);
    
    // Draw code box
    const codeStartY = yPosition;
    const codeLines = doc.splitTextToSize(userCode, pageWidth - 2 * margin - 10);
    const codeHeight = Math.min(codeLines.length * 5, pageHeight - yPosition - 30);
    
    doc.setDrawColor(6, 182, 212);
    doc.setFillColor(245, 245, 245);
    doc.rect(margin, codeStartY - 5, pageWidth - 2 * margin, codeHeight + 5, 'FD');
    
    codeLines.forEach((line: string, index: number) => {
      if (yPosition + 5 > codeStartY + codeHeight - 5) {
        doc.addPage();
        yPosition = margin + 5;
      }
      doc.text(line, margin + 5, yPosition);
      yPosition += 5;
    });
    yPosition += 10;
  }

  // Vulnerabilities Section
  checkPageBreak(20);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('Detailed Vulnerabilities', margin, yPosition);
  yPosition += 10;

  vulnerabilities.forEach((vuln, index) => {
    checkPageBreak(30);
    
    // Vulnerability Header
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text(`Vulnerability ${index + 1}: ${vuln.type || vuln.description.substring(0, 50)}`, margin, yPosition);
    yPosition += 6;

    // Severity Badge
    const severityColors: { [key: string]: number[] } = {
      'Critical': [239, 68, 68],
      'High': [245, 158, 66],
      'Medium': [250, 204, 21],
      'Low': [34, 211, 238]
    };
    const severityColor = severityColors[vuln.severity] || [100, 100, 100];
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(severityColor[0], severityColor[1], severityColor[2]);
    doc.text(`Severity: ${vuln.severity}`, margin, yPosition);
    yPosition += 6;

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(0, 0, 0);
    yPosition += addText(`Status: ${vuln.status}`, 10, 'normal', [0, 0, 0]);

    // Description
    yPosition += addText(`Description: ${vuln.description}`, 10, 'normal', [0, 0, 0]);

    // Code Location
    if (vuln.line && vuln.code) {
      yPosition += addText(`Location: Line ${vuln.line}`, 10, 'normal', [0, 0, 0]);
      doc.setFont('courier', 'normal');
      doc.setTextColor(100, 100, 100);
      const codeText = `  ${vuln.code}`;
      const codeLines = doc.splitTextToSize(codeText, pageWidth - 2 * margin - 10);
      codeLines.forEach((line: string) => {
        checkPageBreak();
        doc.text(line, margin + 5, yPosition);
        yPosition += 4;
      });
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(0, 0, 0);
    }

    // CWE Information
    if (vuln.cwe_id) {
      yPosition += 5;
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(6, 182, 212);
      yPosition += addText('CWE Information', 11, 'bold', [6, 182, 212]);
      
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(0, 0, 0);
      yPosition += addText(`CWE ID: ${vuln.cwe_id} - ${vuln.cwe_name || 'N/A'}`, 10, 'normal', [0, 0, 0]);
      
      if (vuln.cwe_description) {
        yPosition += addText(`Description: ${vuln.cwe_description}`, 10, 'normal', [0, 0, 0]);
      }
      
      if (vuln.cwe_severity) {
        yPosition += addText(`CWE Severity: ${vuln.cwe_severity}`, 10, 'normal', [0, 0, 0]);
      }

      // Mitigation
      if (vuln.mitigation && vuln.mitigation.length > 0) {
        yPosition += 3;
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        yPosition += addText('Mitigation Strategies:', 10, 'bold', [0, 0, 0]);
        doc.setFont('helvetica', 'normal');
        vuln.mitigation.forEach((mit: string) => {
          const mitText = `• ${mit}`;
          yPosition += addText(mitText, 9, 'normal', [0, 0, 0], pageWidth - 2 * margin - 10);
        });
      }

      // References
      if (vuln.references && vuln.references.length > 0) {
        yPosition += 3;
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        yPosition += addText('References:', 10, 'bold', [0, 0, 0]);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(6, 182, 212);
        vuln.references.forEach((ref: string) => {
          yPosition += addText(ref, 9, 'normal', [6, 182, 212], pageWidth - 2 * margin - 10);
        });
        doc.setTextColor(0, 0, 0);
      }
    }

    // Patch Information
    if (vuln.patch) {
      yPosition += 8;
      checkPageBreak(30);
      
      // Patch Section Header
      doc.setFontSize(13);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(34, 211, 238);
      doc.text('Suggested Patch', margin, yPosition);
      yPosition += 8;

      // Patch Explanation/Suggestion
      if (vuln.patch.suggestion) {
        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(0, 0, 0);
        
        // Format the explanation with better structure
        const explanation = String(vuln.patch.suggestion);
        const explanationLines = doc.splitTextToSize(explanation, pageWidth - 2 * margin);
        
        explanationLines.forEach((line: string) => {
          checkPageBreak(6);
          doc.text(line, margin, yPosition);
          yPosition += 5;
        });
        yPosition += 3;
      }
      
      // Patch Code Block
      if (vuln.patch.code) {
        checkPageBreak(20);
        
        doc.setFont('courier', 'normal');
        doc.setFontSize(9);
        const patchCodeText = vuln.patch.code.trim();
        const patchCodeLines = doc.splitTextToSize(patchCodeText, pageWidth - 2 * margin - 10);
        
        let codeY = yPosition;
        
        // Calculate total height needed
        const totalCodeHeight = patchCodeLines.length * 5 + 8;
        const codeFitsOnOnePage = codeY + totalCodeHeight <= pageHeight - margin - 10;
        
        // Draw box background first
        doc.setDrawColor(34, 211, 238);
        doc.setFillColor(240, 253, 250);
        if (codeFitsOnOnePage) {
          // Single box for all code
          doc.rect(margin, codeY - 2, pageWidth - 2 * margin, totalCodeHeight, 'FD');
        } else {
          // Draw box for first page
          const firstPageHeight = pageHeight - codeY - margin - 10;
          doc.rect(margin, codeY - 2, pageWidth - 2 * margin, firstPageHeight, 'FD');
        }
        
        // Render code line by line
        patchCodeLines.forEach((line: string, index: number) => {
          // Check if we need a new page
          if (codeY + 6 > pageHeight - margin - 10) {
            // Draw box for new page before continuing
            doc.addPage();
            codeY = margin + 8;
            
            // Calculate remaining code height
            const remainingLines = patchCodeLines.length - index;
            const remainingHeight = Math.min(remainingLines * 5 + 8, pageHeight - codeY - margin - 10);
            
            // Draw box for new page
            doc.setDrawColor(34, 211, 238);
            doc.setFillColor(240, 253, 250);
            doc.rect(margin, codeY - 2, pageWidth - 2 * margin, remainingHeight, 'FD');
          }
          
          // Draw code text
          doc.setTextColor(6, 150, 200);
          doc.text(line.trim(), margin + 5, codeY);
          codeY += 5;
        });
        
        yPosition = codeY + 5;
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(0, 0, 0);
      } else if (vuln.patch.suggestion) {
        // If there's only explanation but no code, just add some spacing
        yPosition += 5;
      }
    }

    // Complete Vulnerability-Free Code Section
    if (vuln.complete_fixed_code && vuln.status === 'Patched') {
      yPosition += 10;
      checkPageBreak(30);
      
      // Complete Fixed Code Section Header
      doc.setFontSize(13);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(34, 211, 238);
      doc.text('Complete Vulnerability-Free Code', margin, yPosition);
      yPosition += 8;

      // Add description text
      doc.setFontSize(9);
      doc.setFont('helvetica', 'italic');
      doc.setTextColor(100, 100, 100);
      doc.text('This is the complete code with all patches applied:', margin, yPosition);
      yPosition += 6;

      // Complete Fixed Code Block
      checkPageBreak(20);
      
      doc.setFontSize(8);
      doc.setFont('courier', 'normal');
      
      const completeCodeText = vuln.complete_fixed_code.trim();
      const codeLines = doc.splitTextToSize(completeCodeText, pageWidth - 2 * margin - 10);
      const codeLineHeight = 4.5;
      
      // Track code sections per page for box drawing
      const codeSections: Array<{ startY: number; endY: number; startIndex: number; endIndex: number }> = [];
      let pageStartY = yPosition;
      let pageStartIndex = 0;
      let currentY = yPosition;
      
      // First, determine where page breaks will occur
      codeLines.forEach((line: string, index: number) => {
        if (currentY + codeLineHeight > pageHeight - margin - 10) {
          // Save this page's section
          codeSections.push({
            startY: pageStartY,
            endY: currentY,
            startIndex: pageStartIndex,
            endIndex: index
          });
          
          // Move to next page
          pageStartY = margin + 8;
          pageStartIndex = index;
          currentY = pageStartY;
        }
        currentY += codeLineHeight;
      });
      
      // Save the last section
      if (codeLines.length > 0) {
        codeSections.push({
          startY: pageStartY,
          endY: currentY,
          startIndex: pageStartIndex,
          endIndex: codeLines.length
        });
      }
      
      // Now render the code with boxes
      codeSections.forEach((section, sectionIndex) => {
        // Move to the correct page if needed
        if (sectionIndex > 0) {
          doc.addPage();
        }
        
        // Set yPosition to section start
        yPosition = section.startY;
        
        // Draw box for this section
        const boxHeight = section.endY - section.startY + 2;
        doc.setDrawColor(34, 211, 238);
        doc.setFillColor(250, 255, 250);
        doc.rect(margin, section.startY - 2, pageWidth - 2 * margin, boxHeight, 'FD');
        
        // Render code lines for this section
        doc.setFont('courier', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(0, 120, 0);
        
        let lineY = section.startY;
        for (let i = section.startIndex; i < section.endIndex; i++) {
          doc.text(codeLines[i], margin + 5, lineY);
          lineY += codeLineHeight;
        }
        
        // Update yPosition for next content
        yPosition = section.endY;
      });
      
      yPosition += 5;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(0, 0, 0);
    }

    yPosition += 10;
    
    // Draw separator line
    doc.setDrawColor(200, 200, 200);
    doc.line(margin, yPosition, pageWidth - margin, yPosition);
    yPosition += 8;
  });

  // Complete Fixed Code for All Vulnerabilities Section
  if (complete_fixed_code) {
    checkPageBreak(30);
    yPosition += 15;
    
    // Section Header
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(6, 182, 212);
    doc.text('Complete Vulnerability-Free Code (All Patches Applied)', margin, yPosition);
    yPosition += 10;

    // Description
    doc.setFontSize(10);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(100, 100, 100);
    doc.text('This is the complete code with all vulnerabilities patched:', margin, yPosition);
    yPosition += 8;

    // Complete Fixed Code Block
    checkPageBreak(20);
    
    doc.setFontSize(8);
    doc.setFont('courier', 'normal');
    
    const allCodeText = complete_fixed_code.trim();
    const allCodeLines = doc.splitTextToSize(allCodeText, pageWidth - 2 * margin - 10);
    const codeLineHeight = 4.5;
    
    // Track code sections per page for box drawing
    const allCodeSections: Array<{ startY: number; endY: number; startIndex: number; endIndex: number }> = [];
    let allPageStartY = yPosition;
    let allPageStartIndex = 0;
    let allCurrentY = yPosition;
    
    // Determine where page breaks will occur
    allCodeLines.forEach((line: string, index: number) => {
      if (allCurrentY + codeLineHeight > pageHeight - margin - 10) {
        allCodeSections.push({
          startY: allPageStartY,
          endY: allCurrentY,
          startIndex: allPageStartIndex,
          endIndex: index
        });
        
        allPageStartY = margin + 8;
        allPageStartIndex = index;
        allCurrentY = allPageStartY;
      }
      allCurrentY += codeLineHeight;
    });
    
    // Save the last section
    if (allCodeLines.length > 0) {
      allCodeSections.push({
        startY: allPageStartY,
        endY: allCurrentY,
        startIndex: allPageStartIndex,
        endIndex: allCodeLines.length
      });
    }
    
    // Render the code with boxes
    allCodeSections.forEach((section, sectionIndex) => {
      if (sectionIndex > 0) {
        doc.addPage();
      }
      
      yPosition = section.startY;
      
      // Draw box for this section
      const boxHeight = section.endY - section.startY + 2;
      doc.setDrawColor(6, 182, 212);
      doc.setFillColor(240, 253, 250);
      doc.rect(margin, section.startY - 2, pageWidth - 2 * margin, boxHeight, 'FD');
      
      // Render code lines for this section
      doc.setFont('courier', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(0, 120, 0);
      
      let lineY = section.startY;
      for (let i = section.startIndex; i < section.endIndex; i++) {
        doc.text(allCodeLines[i], margin + 5, lineY);
        lineY += codeLineHeight;
      }
      
      yPosition = section.endY;
    });
    
    yPosition += 10;
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(0, 0, 0);
  }

  // Footer
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(150, 150, 150);
    doc.text(
      `Page ${i} of ${totalPages} | Generated by SecurePatcher`,
      pageWidth / 2,
      pageHeight - 10,
      { align: 'center' }
    );
  }

  // Generate filename
  const dateStr = new Date().toISOString().split('T')[0];
  const filename = `SecurePatcher_Report_${dateStr}.pdf`;
  
  // Save PDF
  doc.save(filename);
  
  return filename;
};

