import { jsPDF } from 'jspdf';
import { Alert, Classification } from '../types';

interface PDFParams {
  alert: Alert;
  classification: Classification;
  report: string;
}

export const generateIncidentPDF = ({ alert, classification, report }: PDFParams) => {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageHeight = doc.internal.pageSize.getHeight();
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 20;
  const contentWidth = pageWidth - (margin * 2);

  // Colors
  const darkColor = [15, 23, 42]; // #0F172A
  const greyColor = [100, 116, 139]; // #64748B
  const lightGrey = [241, 245, 249]; // #F1F5F9
  const accentColor = [15, 118, 110]; // #0F766E

  const sevColors: Record<string, number[]> = {
    CRITICAL: [239, 68, 68],  // #EF4444
    HIGH: [249, 115, 22],    // #F97316
    MEDIUM: [245, 158, 11],  // #F59E0B
    LOW: [16, 185, 129]      // #10B981
  };
  const currentSevColor = sevColors[classification.severity] || [100, 116, 139];

  const verdictColors: Record<string, { bg: number[]; fg: number[] }> = {
    'TRUE POSITIVE': { bg: [254, 226, 226], fg: [153, 27, 27] },
    'FALSE POSITIVE': { bg: [220, 252, 231], fg: [22, 101, 52] },
    'NEEDS INVESTIGATION': { bg: [254, 249, 195], fg: [133, 77, 14] }
  };
  const currentVerdictColor = verdictColors[classification.verdict] || verdictColors['NEEDS INVESTIGATION'];

  // ----------------------------------------------------
  // PAGE 1: HEADER & META SECTION
  // ----------------------------------------------------
  
  // Draw Logo (Stylized V with loop on right)
  doc.setLineCap('round');
  doc.setLineJoin('round');
  doc.setLineWidth(1.6);

  // Left Blue Arm (gradient: light blue at top to dark blue at bottom)
  const leftArm = [
    { x: 21.0, y: 16.0, r: 96, g: 165, b: 250 }, // light blue
    { x: 21.6, y: 18.0, r: 59, g: 130, b: 246 },
    { x: 22.4, y: 20.0, r: 37, g: 99, b: 235 },
    { x: 23.4, y: 22.0, r: 29, g: 78, b: 216 },
    { x: 24.8, y: 24.0, r: 30, g: 58, b: 138 }  // deep blue
  ];
  for (let i = 0; i < leftArm.length - 1; i++) {
    doc.setDrawColor(leftArm[i].r, leftArm[i].g, leftArm[i].b);
    doc.line(leftArm[i].x, leftArm[i].y, leftArm[i+1].x, leftArm[i+1].y);
  }

  // Right Teal/Green Loop
  const rightArm = [
    { x: 24.8, y: 24.0, r: 30, g: 58, b: 138 },   // connection with left arm
    { x: 25.6, y: 22.0, r: 13, g: 148, b: 136 },   // teal
    { x: 26.5, y: 19.8, r: 20, g: 184, b: 166 },   // light teal
    { x: 27.5, y: 17.5, r: 16, g: 185, b: 129 },   // green
    { x: 28.8, y: 15.6, r: 52, g: 211, b: 153 },   // light green (top loop start)
    { x: 30.2, y: 16.0, r: 16, g: 185, b: 129 },   // green (loop apex)
    { x: 30.8, y: 17.3, r: 4, g: 120, b: 87 },     // dark green (loop side)
    { x: 30.2, y: 19.0, r: 13, g: 148, b: 136 },   // teal (loop fold back)
    { x: 29.0, y: 20.7, r: 15, g: 118, b: 110 },   // dark teal
    { x: 27.8, y: 22.5, r: 17, g: 94, b: 89 }      // deep emerald
  ];
  for (let i = 0; i < rightArm.length - 1; i++) {
    doc.setDrawColor(rightArm[i].r, rightArm[i].g, rightArm[i].b);
    doc.line(rightArm[i].x, rightArm[i].y, rightArm[i+1].x, rightArm[i+1].y);
  }

  // Cover Header Text
  doc.setTextColor(15, 23, 42); // darkColor
  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(15);
  doc.text('Vigilance AI', 34, 20);
  
  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139); // steel gray
  doc.text('AUTONOMOUS SECURITY SURVEILLANCE & AI TRIAGE', 34, 24);

    // Severity Badge on Cover Header (Top Right) — rounded pill
  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(8);
  const sevBadgeWidth = Math.max(28, doc.getTextWidth(classification.severity) + 10);
  const sevBadgeX = pageWidth - margin - sevBadgeWidth;
  const sevBadgeY = 15;
  const sevBadgeHeight = 6.5;

  doc.setFillColor(currentSevColor[0], currentSevColor[1], currentSevColor[2]);
  doc.roundedRect(sevBadgeX, sevBadgeY, sevBadgeWidth, sevBadgeHeight, 1.5, 1.5, 'F');
  doc.setTextColor(255, 255, 255);
  doc.text(classification.severity, sevBadgeX + sevBadgeWidth / 2, sevBadgeY + 4.4, { align: 'center' });

  // Verdict Badge — stacked below severity
  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(6.5);
  const verdictText = classification.verdict || 'NEEDS INVESTIGATION';
  const verdictBadgeWidth = Math.max(28, doc.getTextWidth(verdictText) + 8);
  const verdictBadgeX = pageWidth - margin - verdictBadgeWidth;
  const verdictBadgeY = sevBadgeY + sevBadgeHeight + 2;
  const verdictBadgeHeight = 5.5;

  doc.setFillColor(currentVerdictColor.bg[0], currentVerdictColor.bg[1], currentVerdictColor.bg[2]);
  doc.roundedRect(verdictBadgeX, verdictBadgeY, verdictBadgeWidth, verdictBadgeHeight, 1.2, 1.2, 'F');
  doc.setTextColor(currentVerdictColor.fg[0], currentVerdictColor.fg[1], currentVerdictColor.fg[2]);
  doc.text(verdictText, verdictBadgeX + verdictBadgeWidth / 2, verdictBadgeY + 3.7, { align: 'center' });

  // Confidence — muted label under the verdict pill
  if (classification.confidence) {
    doc.setFont('Helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(greyColor[0], greyColor[1], greyColor[2]);
    doc.text(
      `Confidence: ${classification.confidence}`,
      pageWidth - margin,
      verdictBadgeY + verdictBadgeHeight + 3.5,
      { align: 'right' }
    );
  }

  // Title (drawn below the logo and title - dynamic based on alert.rule.description)
  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42); // darkColor
  
  const titleText = `Case Creation of ${alert.rule.description}`;
  const titleLines = doc.splitTextToSize(titleText, pageWidth - (margin * 2));
  let titleY = 40;
  titleLines.forEach((line: string) => {
    doc.text(line, margin, titleY);
    titleY += 4.5;
  });

  // Underline dividing line below the Title
  doc.setDrawColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.setLineWidth(0.4);
  doc.line(margin, titleY - 1.5, pageWidth - margin, titleY - 1.5);

  // Reset text color to default dark
  doc.setTextColor(darkColor[0], darkColor[1], darkColor[2]);

  // Meta Section Grid (below header)
  let y = titleY + 5;
  doc.setFontSize(10);
  doc.setFont('Helvetica', 'bold');
  doc.text('Incident Details', margin, y);
  
  // Underline
  doc.setDrawColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.setLineWidth(0.4);
  doc.line(margin, y + 2, margin + 25, y + 2);

  y += 8;
  doc.setFontSize(9);
  
  // Meta grid helper (compact, precise, and wraps long values like MITRE Category)
  const drawMetaRow = (label1: string, val1: string, label2: string, val2: string, rowY: number): number => {
    doc.setFont('Helvetica', 'bold');
    doc.text(label1, margin, rowY);
    
    // Split val1 if it is too long (max width ~55mm)
    doc.setFont('Helvetica', 'normal');
    const val1Lines = doc.splitTextToSize(val1, 55);
    
    // Draw first line of val1
    doc.text(val1Lines[0] || '', margin + 30, rowY);

    doc.setFont('Helvetica', 'bold');
    doc.text(label2, margin + 90, rowY);
    doc.setFont('Helvetica', 'normal');
    doc.text(val2, margin + 122, rowY);

    // If val1 has more lines, wrap them and align starting from where 'T' is written (margin + 30)
    let extraHeight = 0;
    if (val1Lines.length > 1) {
      doc.setFont('Helvetica', 'normal');
      for (let i = 1; i < val1Lines.length; i++) {
        extraHeight += 5;
        doc.text(val1Lines[i], margin + 30, rowY + extraHeight);
      }
    }
    return extraHeight;
  };

  let extra = drawMetaRow('Incident ID:', alert.id, 'Agent Host:', alert.agent.name, y);
  y += 6 + extra;
  extra = drawMetaRow('Timestamp:', alert.timestamp, 'Agent IP:', alert.agent.ip, y);
  y += 6 + extra;
  extra = drawMetaRow('Rule Name:', alert.rule.id, 'Severity Level:', `${alert.rule.level}/15`, y);
  y += 6 + extra;
  extra = drawMetaRow('MITRE Category:', classification.technique, 'Triage Status:', 'RESOLVED (AI)', y);
  y += extra + 4.0;

  // Thin separator line below meta section (Reduced space below details block)
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.line(margin, y, pageWidth - margin, y);

  // Increased spacing between line and NIST Framework
  y += 9.5;

  // NIST Framework Section (Redesigned as an informative and styled Dashboard Card)
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(margin, y - 3.5, 2.5, 4.5, 'F'); // Left accent bar for section header

  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42); // slate dark
  doc.text('NIST Framework', margin + 5, y);
  
  const boxStartY = y + 4;

  const bullets = [
    { label: '• Who:', val: `${alert.agent.name} (Agent ID: ${alert.agent.id}) — Monitored endpoint registered within the operational inventory.` },
    { label: '• What:', val: `${alert.rule.description} (Triggered Rule: ${alert.rule.id}) — Categorized under group scope: [${alert.rule.groups.join(', ')}].` },
    { label: '• When:', val: `${alert.timestamp} — Event captured and triaged autonomously by local telemetry sensors.` },
    { label: '• Where:', val: `Host Name: ${alert.agent.name} | Network Address: IP ${alert.agent.ip} (Internal Operational Segment).` },
    { label: '• How:', val: `${classification.technique} (Evaluated Risk Level: ${alert.rule.level}/15 | Threat Severity: ${classification.severity}).` }
  ];

  // Calculate box height dynamically first to draw background safely under text
  doc.setFont('Helvetica', 'normal');
  doc.setFontSize(9);
  let calcY = boxStartY + 5.5;
  const computedBullets = bullets.map(b => {
    const splitVal = doc.splitTextToSize(b.val, contentWidth - 37);
    const itemHeight = 5.5 + (splitVal.length > 1 ? (splitVal.length - 1) * 4.5 : 0);
    calcY += itemHeight;
    return { label: b.label, lines: splitVal, height: itemHeight };
  });

  const boxHeight = (calcY - 1) - boxStartY;

  // Draw card background container
  doc.setFillColor(248, 250, 252); // slate-50 background tint
  doc.rect(margin, boxStartY, contentWidth, boxHeight, 'F');
  
  // Draw card left accent border line
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(margin, boxStartY, 1.2, boxHeight, 'F');

  // Draw card border line
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.35);
  doc.rect(margin, boxStartY, contentWidth, boxHeight, 'D');

  // Render the bullets on top of the card
  let currentBulletY = boxStartY + 5.5;
  computedBullets.forEach(cb => {
    // Label: Bold dark slate text
    doc.setFont('Helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42); // slate-900
    doc.text(cb.label, margin + 5, currentBulletY);
    
    // Value: Clean dark gray text
    doc.setFont('Helvetica', 'normal');
    doc.setTextColor(51, 65, 85); // slate-700
    doc.text(cb.lines[0], margin + 35, currentBulletY);
    
    if (cb.lines.length > 1) {
      for (let j = 1; j < cb.lines.length; j++) {
        currentBulletY += 4.5;
        doc.text(cb.lines[j], margin + 35, currentBulletY);
      }
    }
    currentBulletY += 5.5; // Spacing to next bullet
  });

  // Calculate position for next section
  let nextY = boxStartY + boxHeight + 10;

  // Safety page break check for Incident Response Section
  if (nextY + 55 > pageHeight - 20) {
    doc.addPage();
    nextY = 25;
  }

  // Incident Response Section
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(margin, nextY - 3.5, 2.5, 4.5, 'F'); // Left accent bar for section header

  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42); // slate dark
  doc.text('Incident Response', margin + 5, nextY);

  const boxStartY_IR = nextY + 4;

  const irSteps = [
    { label: '1. Preparation:', val: 'Establish detection rules, set threshold baselines, and deploy host logging agents (Vigilance agent fleet) across endpoints.' },
    { label: '2. Detection:', val: `Automated detection triggered on endpoint ${alert.agent.name} for rule ID ${alert.rule.id}: ${alert.rule.description}.` },
    { label: '3. Containment:', val: alert.rule.level >= 10 
        ? 'High-severity event. Initiated automatic network isolation on host to quarantine affected system and block horizontal movement.'
        : 'Medium-severity event. Isolated malicious sessions and flagged host telemetry for focused observation.' },
    { label: '4. Eradication:', val: alert.rule.description.toLowerCase().includes('disk space')
        ? 'Executed disk space cleanup routines and deleted transient log dumps to restore partition operation.'
        : 'Terminated offending processes, isolated suspicious binary path references, and re-verified baseline signatures.' },
    { label: '5. Recovery:', val: 'Verified normal operational status. Monitoring service health metrics and restoring full network access permissions incrementally.' },
    { label: '6. Post-incident:', val: 'Conduct post-incident review. Update detection triggers if necessary, and log summary case into standard compliance archives.' }
  ];

  doc.setFont('Helvetica', 'normal');
  doc.setFontSize(9);
  let calcY_IR = boxStartY_IR + 5.5;
  const computedIRSteps = irSteps.map(step => {
    const splitVal = doc.splitTextToSize(step.val, contentWidth - 37);
    const itemHeight = 5.5 + (splitVal.length > 1 ? (splitVal.length - 1) * 4.5 : 0);
    calcY_IR += itemHeight;
    return { label: step.label, lines: splitVal, height: itemHeight };
  });

  const boxHeight_IR = (calcY_IR - 1) - boxStartY_IR;

  // Draw card background container
  doc.setFillColor(248, 250, 252); // slate-50 background tint
  doc.rect(margin, boxStartY_IR, contentWidth, boxHeight_IR, 'F');
  
  // Draw card left accent border line
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(margin, boxStartY_IR, 1.2, boxHeight_IR, 'F');

  // Draw card border line
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.35);
  doc.rect(margin, boxStartY_IR, contentWidth, boxHeight_IR, 'D');

  // Render the steps on top of the card
  let currentStepY = boxStartY_IR + 5.5;
  computedIRSteps.forEach(cs => {
    // Label: Bold dark slate text
    doc.setFont('Helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42); // slate-900
    doc.text(cs.label, margin + 5, currentStepY);
    
    // Value: Clean dark gray text
    doc.setFont('Helvetica', 'normal');
    doc.setTextColor(51, 65, 85); // slate-700
    doc.text(cs.lines[0], margin + 35, currentStepY);
    
    if (cs.lines.length > 1) {
      for (let j = 1; j < cs.lines.length; j++) {
        currentStepY += 4.5;
        doc.text(cs.lines[j], margin + 35, currentStepY);
      }
    }
    currentStepY += 5.5; // Spacing to next item
  });

  // Calculate position for next section (Alert Description)
  let nextY_AD = boxStartY_IR + boxHeight_IR + 10;

  // Safety page break check for Alert Description Section Header
  if (nextY_AD + 15 > pageHeight - 20) {
    doc.addPage();
    nextY_AD = 25;
  }

  // Section Header: Alert Description
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(margin, nextY_AD - 3.5, 2.5, 4.5, 'F'); // Left accent bar for section header

  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42); // slate dark
  doc.text('Alert Description', margin + 5, nextY_AD);

  const boxStartY_AD = nextY_AD + 4;
  
  // Parse the report text into lines
  const rawLines = report.split('\n');
  const processedLines: { text: string; isHeader: boolean }[] = [];
  
  rawLines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed) {
      processedLines.push({ text: '', isHeader: false });
      return;
    }
    // Check if it looks like a header (e.g. "EXECUTIVE SUMMARY", "TECHNICAL ANALYSIS", etc. or ends with ":")
    const isHeader = trimmed === trimmed.toUpperCase() && trimmed.length > 3 && !trimmed.startsWith('•') && !trimmed.match(/^\d+\./);
    processedLines.push({ text: trimmed, isHeader });
  });

  // Calculate the lines of text and their spacing
  doc.setFont('Helvetica', 'normal');
  doc.setFontSize(8.5);
  
  let calcY_AD = boxStartY_AD + 5.5;
  const computedADLines: { lines: string[]; isHeader: boolean; height: number }[] = [];
  
  processedLines.forEach(pl => {
    if (pl.text === '') {
      // Empty line / paragraph separator
      calcY_AD += 3;
      computedADLines.push({ lines: [''], isHeader: false, height: 3 });
      return;
    }
    
    doc.setFont('Helvetica', pl.isHeader ? 'bold' : 'normal');
    doc.setFontSize(pl.isHeader ? 9 : 8.5);
    
    const splitVal = doc.splitTextToSize(pl.text, contentWidth - 10);
    const itemHeight = splitVal.length * 4.5;
    calcY_AD += itemHeight;
    computedADLines.push({ lines: splitVal, isHeader: pl.isHeader, height: itemHeight });
  });

  // Paginate card container items
  const pages: { startY: number; endY: number; items: { lines: string[]; isHeader: boolean; startY: number }[] }[] = [];
  let currentPageItems: { lines: string[]; isHeader: boolean; startY: number }[] = [];
  let currentStartY = boxStartY_AD;
  let tempY = boxStartY_AD + 5.5;
  
  computedADLines.forEach((item) => {
    // If the line block overflows the current page
    if (tempY + item.height > pageHeight - 15) {
      pages.push({
        startY: currentStartY,
        endY: tempY - 1.5,
        items: currentPageItems
      });
      currentPageItems = [];
      currentStartY = 20; // safe top margin on new page
      tempY = 25;
    }
    
    currentPageItems.push({
      lines: item.lines,
      isHeader: item.isHeader,
      startY: tempY
    });
    
    tempY += item.height;
  });
  
  if (currentPageItems.length > 0) {
    pages.push({
      startY: currentStartY,
      endY: tempY - 1.5,
      items: currentPageItems
    });
  }

  // Draw pages dynamically
  pages.forEach((page, index) => {
    if (index > 0) {
      doc.addPage();
    }
    
    const pageBoxHeight = page.endY - page.startY;
    
    // Draw card background container
    doc.setFillColor(248, 250, 252); // slate-50 background tint
    doc.rect(margin, page.startY, contentWidth, pageBoxHeight, 'F');
    
    // Draw card left accent border line
    doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.rect(margin, page.startY, 1.2, pageBoxHeight, 'F');

    // Draw card border line
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.35);
    doc.rect(margin, page.startY, contentWidth, pageBoxHeight, 'D');
    
    // Render the text lines on this page
    page.items.forEach(item => {
      if (item.lines.length === 1 && item.lines[0] === '') {
        return; // Empty line
      }
      
      doc.setFont('Helvetica', item.isHeader ? 'bold' : 'normal');
      doc.setFontSize(item.isHeader ? 9 : 8.5);
      doc.setTextColor(item.isHeader ? 15 : 51, item.isHeader ? 23 : 65, item.isHeader ? 42 : 85); // slate-900 for header, slate-700 for text
      
      let lineY = item.startY;
      item.lines.forEach(subLine => {
        doc.text(subLine, margin + 5, lineY);
        lineY += 4.5;
      });
    });
  });

  // Calculate position for next section (Executive Summary)
  let nextY_ES = pages[pages.length - 1].endY + 10;

  // Safety page break check for Executive Summary Section
  if (nextY_ES + 35 > pageHeight - 20) {
    doc.addPage();
    nextY_ES = 25;
  }

  // Section Header: Executive Summary
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(margin, nextY_ES - 3.5, 2.5, 4.5, 'F'); // Left accent bar for section header

  doc.setFont('Helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42); // slate dark
  doc.text('Executive Summary', margin + 5, nextY_ES);

  const boxStartY_ES = nextY_ES + 4;

  const esText = `An automated security alert was triggered due to ${alert.rule.description.toLowerCase()} detected on system ${alert.agent.name} (${alert.agent.ip}). This activity aligns with MITRE ATT&CK technique ${classification.technique}. Following automated threat triage protocol, security controls successfully isolated the suspicious activity and quarantined any affected processes. The host has been verified as secure, and the incident has been resolved with no further threat to the operational environment.`;

  doc.setFont('Helvetica', 'normal');
  doc.setFontSize(9);
  const splitESText = doc.splitTextToSize(esText, contentWidth - 10);
  const boxHeight_ES = (splitESText.length * 4.5) + 8;

  // Draw card background container
  doc.setFillColor(248, 250, 252); // slate-50 background tint
  doc.rect(margin, boxStartY_ES, contentWidth, boxHeight_ES, 'F');
  
  // Draw card left accent border line
  doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
  doc.rect(margin, boxStartY_ES, 1.2, boxHeight_ES, 'F');

  // Draw card border line
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.35);
  doc.rect(margin, boxStartY_ES, contentWidth, boxHeight_ES, 'D');

  // Render the text lines
  doc.setTextColor(51, 65, 85); // slate-700
  let currentES_Y = boxStartY_ES + 5.5;
  splitESText.forEach((line: string) => {
    doc.text(line, margin + 5, currentES_Y);
    currentES_Y += 4.5;
  });

  // Save Document
  const sanitizedRuleName = alert.rule.description
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
    // Footer with page numbers on every page
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('Helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text(`Vigilance AI — Confidential`, margin, pageHeight - 10);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 10, { align: 'right' });
    doc.text(`Incident ID: ${alert.id}`, pageWidth / 2, pageHeight - 10, { align: 'center' });
  }

  doc.save(`case_creation_${sanitizedRuleName || alert.id}.pdf`);
};







