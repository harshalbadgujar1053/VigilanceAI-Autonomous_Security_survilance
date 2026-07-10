import React, { useEffect, useRef } from 'react';

interface CyberBackgroundProps {
  mode?: 'light' | 'dark';
}

export default function CyberBackground({ mode = 'light' }: CyberBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    // Handle Resize
    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    // Points on sphere (Holographic Globe) for dark mode
    interface Point3D {
      x: number;
      y: number;
      z: number;
      baseX: number;
      baseY: number;
      baseZ: number;
      size: number;
      opacity: number;
    }

    const globePoints: Point3D[] = [];
    const baseRadius = Math.min(width, height) * 0.35;
    
    // Generate procedurally continent points on sphere
    const isLand = (lat: number, lon: number) => {
      // Procedural noise for continent shape
      const s = Math.sin(lat * 3.2) * Math.sin(lon * 2.1) + Math.cos(lat * 1.5) * Math.cos(lon * 3.5);
      const sub = Math.sin(lat * 8) * Math.cos(lon * 6.5) * 0.25;
      return s + sub > 0.12;
    };

    // Generate globe land points
    const latStep = 40;
    const lonStep = 80;
    for (let i = 0; i < latStep; i++) {
      const lat = (i / latStep) * Math.PI - Math.PI / 2; // -pi/2 to pi/2
      const cosLat = Math.cos(lat);
      const sinLat = Math.sin(lat);
      
      // Calculate how many points on this latitude ring
      const ringCircumference = 2 * Math.PI * Math.abs(cosLat);
      const ringPointsCount = Math.floor(ringCircumference * 24); // scale points count

      for (let j = 0; j < ringPointsCount; j++) {
        const lon = (j / ringPointsCount) * 2 * Math.PI - Math.PI; // -pi to pi
        
        if (isLand(lat, lon)) {
          // Spherical to Cartesian
          const x = cosLat * Math.sin(lon);
          const y = sinLat;
          const z = cosLat * Math.cos(lon);
          
          globePoints.push({
            x: x * baseRadius,
            y: y * baseRadius,
            z: z * baseRadius,
            baseX: x * baseRadius,
            baseY: y * baseRadius,
            baseZ: z * baseRadius,
            size: Math.random() * 1.3 + 0.6,
            opacity: Math.random() * 0.45 + 0.55
          });
        }
      }
    }

    // Latitude & Longitude wireframe rings
    const rings: { points: {x: number, y: number, z: number}[] }[] = [];
    
    // 5 Latitudes
    for (let i = 1; i < 5; i++) {
      const lat = (i / 5) * Math.PI - Math.PI / 2;
      const cosLat = Math.cos(lat);
      const sinLat = Math.sin(lat);
      const ringPoints = [];
      for (let j = 0; j <= 50; j++) {
        const lon = (j / 50) * 2 * Math.PI;
        ringPoints.push({
          x: cosLat * Math.sin(lon) * baseRadius,
          y: sinLat * baseRadius,
          z: cosLat * Math.cos(lon) * baseRadius
        });
      }
      rings.push({ points: ringPoints });
    }

    // 6 Longitudes
    for (let i = 0; i < 6; i++) {
      const lon = (i / 6) * 2 * Math.PI;
      const ringPoints = [];
      for (let j = 0; j <= 50; j++) {
        const lat = (j / 50) * Math.PI - Math.PI / 2;
        ringPoints.push({
          x: Math.cos(lat) * Math.sin(lon) * baseRadius,
          y: Math.sin(lat) * baseRadius,
          z: Math.cos(lat) * Math.cos(lon) * baseRadius
        });
      }
      rings.push({ points: ringPoints });
    }

    // Network connection routes on land
    const connectionLines: { p1Idx: number, p2Idx: number, pct: number, speed: number }[] = [];
    if (globePoints.length > 0) {
      for (let i = 0; i < 12; i++) {
        const p1Idx = Math.floor(Math.random() * globePoints.length);
        const p2Idx = Math.floor(Math.random() * globePoints.length);
        connectionLines.push({
          p1Idx,
          p2Idx,
          pct: Math.random(),
          speed: 0.003 + Math.random() * 0.007
        });
      }
    }

    // Background stars / floating nodes
    const bgStars: { x: number; y: number; size: number; speed: number; opacity: number }[] = [];
    for (let i = 0; i < 50; i++) {
      bgStars.push({
        x: Math.random() * width,
        y: Math.random() * height,
        size: Math.random() * 1.5 + 0.5,
        speed: Math.random() * 0.12 + 0.04,
        opacity: Math.random() * 0.5 + 0.3
      });
    }

    // Light Mode particles
    const netPoints: { x: number; y: number; vx: number; vy: number; radius: number }[] = [];
    for (let i = 0; i < 35; i++) {
      netPoints.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 1.8 + 0.8
      });
    }

    let angleY = 0;
    let angleX = 0.18; // slight Tilt

    // Draw Loop
    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      const isDark = mode === 'dark';

      // Theme Colors Configuration
      const gridColor = isDark ? 'rgba(6, 182, 212, 0.02)' : 'rgba(13, 148, 136, 0.04)';
      const starColor = isDark ? 'rgba(56, 189, 248, 0.8)' : 'rgba(14, 165, 233, 0.35)';

      const ringBackCol = isDark ? 'rgba(6, 182, 212, 0.04)' : 'rgba(13, 148, 136, 0.05)';
      const ringFrontCol = isDark ? 'rgba(6, 182, 212, 0.12)' : 'rgba(13, 148, 136, 0.18)';

      const getPtBackCol = (alpha: number) => isDark ? `rgba(6, 182, 212, ${alpha})` : `rgba(13, 148, 136, ${alpha * 0.7})`;
      const getPtFrontCol = (alpha: number) => isDark ? `rgba(56, 189, 248, ${alpha})` : `rgba(13, 148, 136, ${alpha})`;

      const connBackCol = isDark ? 'rgba(6, 182, 212, 0.06)' : 'rgba(13, 148, 136, 0.06)';

      const connGradStart = isDark ? 'rgba(6, 182, 212, 0.18)' : 'rgba(14, 165, 233, 0.25)';
      const connGradMid = isDark ? 'rgba(16, 185, 129, 0.35)' : 'rgba(13, 148, 136, 0.45)';
      const connGradEnd = isDark ? 'rgba(56, 189, 248, 0.18)' : 'rgba(2, 132, 199, 0.2)';

      const packetShadow = isDark ? '#06b6d4' : '#0d9488';
      const packetFill = isDark ? '#ffffff' : '#0f172a';

      const auraColor1 = isDark ? 'rgba(6, 182, 212, 0.04)' : 'rgba(13, 148, 136, 0.05)';
      const auraColor2 = isDark ? 'rgba(16, 185, 129, 0.01)' : 'rgba(14, 165, 233, 0.02)';

      // Space background gradient fill
      const gradient = ctx.createRadialGradient(
        width * 0.7, height * 0.5, 10,
        width * 0.7, height * 0.5, Math.max(width, height) * 0.75
      );
      if (isDark) {
        gradient.addColorStop(0, '#03112a');
        gradient.addColorStop(0.5, '#020712');
        gradient.addColorStop(1, '#010309');
      } else {
        gradient.addColorStop(0, '#ffffff');
        gradient.addColorStop(0.5, '#f8fafc');
        gradient.addColorStop(1, '#f1f5f9');
      }
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, width, height);

      // Ambient cyber grid
      ctx.strokeStyle = gridColor;
      ctx.lineWidth = 1;
      const gridGap = 70;
      for (let x = 0; x < width; x += gridGap) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridGap) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Background stars / floating nodes
      ctx.fillStyle = starColor;
      for (const star of bgStars) {
        star.y -= star.speed;
        if (star.y < 0) {
          star.y = height;
          star.x = Math.random() * width;
        }
        ctx.globalAlpha = star.opacity * (0.4 + 0.6 * Math.sin(Date.now() * 0.0015 + star.x));
        ctx.fillRect(star.x, star.y, star.size, star.size);
      }
      ctx.globalAlpha = 1.0;

      // Globe position and dynamic scale
      const centerX = width > 900 ? width * 0.68 : width * 0.5;
      const centerY = height * 0.5;
      const activeRadius = Math.min(width, height) * (width > 900 ? 0.38 : 0.35);

      // Rotate
      angleY += 0.0015;

      const cosY = Math.cos(angleY);
      const sinY = Math.sin(angleY);
      const cosX = Math.cos(angleX);
      const sinX = Math.sin(angleX);

      // Project 3D points
      const project3D = (pt: {x: number, y: number, z: number}) => {
        let x1 = pt.x * cosY - pt.z * sinY;
        let z1 = pt.x * sinY + pt.z * cosY;
        let y2 = pt.y * cosX - z1 * sinX;
        let z2 = pt.y * sinX + z1 * cosX;

        const distance = 850;
        const scale = distance / (distance + z2);
        const projX = centerX + x1 * scale;
        const projY = centerY + y2 * scale;
        
        return {
          x: projX,
          y: projY,
          z: z2,
          scale
        };
      };

      // Draw wireframe rings (back half)
      ctx.lineWidth = 0.5;
      for (const ring of rings) {
        ctx.beginPath();
        let started = false;
        for (const pt of ring.points) {
          const scaledPt = { x: (pt.x / baseRadius) * activeRadius, y: (pt.y / baseRadius) * activeRadius, z: (pt.z / baseRadius) * activeRadius };
          const proj = project3D(scaledPt);
          if (proj.z > 0) {
            if (!started) {
              ctx.moveTo(proj.x, proj.y);
              started = true;
            } else {
              ctx.lineTo(proj.x, proj.y);
            }
          }
        }
        ctx.strokeStyle = ringBackCol;
        ctx.stroke();
      }

      // Draw points (back half)
      for (const pt of globePoints) {
        if (pt.z > 0) {
          const scaledPt = { x: (pt.baseX / baseRadius) * activeRadius, y: (pt.baseY / baseRadius) * activeRadius, z: (pt.baseZ / baseRadius) * activeRadius };
          const proj = project3D(scaledPt);
          if (proj.z > 0) {
            const alpha = (1 - proj.z / activeRadius) * pt.opacity * 0.18;
            ctx.fillStyle = getPtBackCol(alpha);
            ctx.beginPath();
            ctx.arc(proj.x, proj.y, pt.size * proj.scale, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      }

      // Draw network connections (back half)
      ctx.lineWidth = 0.8;
      for (const line of connectionLines) {
        const p1 = globePoints[line.p1Idx];
        const p2 = globePoints[line.p2Idx];
        if (p1 && p2) {
          const scaledP1 = { x: (p1.baseX / baseRadius) * activeRadius, y: (p1.baseY / baseRadius) * activeRadius, z: (p1.baseZ / baseRadius) * activeRadius };
          const scaledP2 = { x: (p2.baseX / baseRadius) * activeRadius, y: (p2.baseY / baseRadius) * activeRadius, z: (p2.baseZ / baseRadius) * activeRadius };
          const proj1 = project3D(scaledP1);
          const proj2 = project3D(scaledP2);
          if (proj1.z > 0 && proj2.z > 0) {
            ctx.strokeStyle = connBackCol;
            ctx.beginPath();
            ctx.moveTo(proj1.x, proj1.y);
            ctx.lineTo(proj2.x, proj2.y);
            ctx.stroke();
          }
        }
      }

      // Draw wireframe rings (front half)
      ctx.lineWidth = 1.0;
      for (const ring of rings) {
        ctx.beginPath();
        let started = false;
        for (const pt of ring.points) {
          const scaledPt = { x: (pt.x / baseRadius) * activeRadius, y: (pt.y / baseRadius) * activeRadius, z: (pt.z / baseRadius) * activeRadius };
          const proj = project3D(scaledPt);
          if (proj.z <= 0) {
            if (!started) {
              ctx.moveTo(proj.x, proj.y);
              started = true;
            } else {
              ctx.lineTo(proj.x, proj.y);
            }
          }
        }
        ctx.strokeStyle = ringFrontCol;
        ctx.stroke();
      }

      // Draw points (front half)
      for (const pt of globePoints) {
        if (pt.z <= 0) {
          const scaledPt = { x: (pt.baseX / baseRadius) * activeRadius, y: (pt.baseY / baseRadius) * activeRadius, z: (pt.baseZ / baseRadius) * activeRadius };
          const proj = project3D(scaledPt);
          if (proj.z <= 0) {
            const depthFactor = Math.max(0, 1 - (proj.z + activeRadius) / (2 * activeRadius));
            const alpha = depthFactor * pt.opacity * 0.9;
            ctx.fillStyle = getPtFrontCol(alpha);
            ctx.beginPath();
            ctx.arc(proj.x, proj.y, pt.size * proj.scale * 1.1, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      }

      // Draw network connections (front half) & data packets
      for (const line of connectionLines) {
        const p1 = globePoints[line.p1Idx];
        const p2 = globePoints[line.p2Idx];
        if (p1 && p2) {
          const scaledP1 = { x: (p1.baseX / baseRadius) * activeRadius, y: (p1.baseY / baseRadius) * activeRadius, z: (p1.baseZ / baseRadius) * activeRadius };
          const scaledP2 = { x: (p2.baseX / baseRadius) * activeRadius, y: (p2.baseY / baseRadius) * activeRadius, z: (p2.baseZ / baseRadius) * activeRadius };
          const proj1 = project3D(scaledP1);
          const proj2 = project3D(scaledP2);
          if (proj1.z <= 0 && proj2.z <= 0) {
            const gradientLine = ctx.createLinearGradient(proj1.x, proj1.y, proj2.x, proj2.y);
            gradientLine.addColorStop(0, connGradStart);
            gradientLine.addColorStop(0.5, connGradMid);
            gradientLine.addColorStop(1, connGradEnd);
            ctx.strokeStyle = gradientLine;
            ctx.lineWidth = 1.0;
            ctx.beginPath();
            ctx.moveTo(proj1.x, proj1.y);
            ctx.lineTo(proj2.x, proj2.y);
            ctx.stroke();

            // Draw animated data packet
            line.pct += line.speed;
            if (line.pct > 1) {
              line.pct = 0;
              line.speed = 0.003 + Math.random() * 0.007;
            }
            const packetX = proj1.x + (proj2.x - proj1.x) * line.pct;
            const packetY = proj1.y + (proj2.y - proj1.y) * line.pct;
            
            ctx.shadowColor = packetShadow;
            ctx.shadowBlur = 6;
            ctx.fillStyle = packetFill;
            ctx.beginPath();
            ctx.arc(packetX, packetY, 2.5, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0; // reset
          }
        }
      }

      // Ambient aura around globe
      const aura = ctx.createRadialGradient(centerX, centerY, activeRadius * 0.8, centerX, centerY, activeRadius * 1.35);
      aura.addColorStop(0, auraColor1);
      aura.addColorStop(0.5, auraColor2);
      aura.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = aura;
      ctx.beginPath();
      ctx.arc(centerX, centerY, activeRadius * 1.5, 0, Math.PI * 2);
      ctx.fill();

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, [mode]);

  return (
    <canvas
      ref={canvasRef}
      id="vanta-background-root"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: -1,
        width: '100vw',
        height: '100vh',
        overflow: 'hidden',
        pointerEvents: 'none',
        display: 'block',
      }}
    />
  );
}

