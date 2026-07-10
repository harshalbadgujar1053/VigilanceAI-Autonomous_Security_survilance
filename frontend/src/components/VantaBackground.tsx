import React, { useEffect, useRef } from 'react';

declare global {
  interface Window {
    VANTA: any;
  }
}

export default function VantaBackground() {
  const vantaContainerRef = useRef<HTMLDivElement>(null);
  const vantaInstanceRef = useRef<any>(null);

  useEffect(() => {
    let checkInterval: any;

    const initVanta = () => {
      if (window.VANTA && window.VANTA.NET && vantaContainerRef.current) {
        // Destroy existing instance if any
        if (vantaInstanceRef.current) {
          try {
            vantaInstanceRef.current.destroy();
          } catch (e) {
            console.error('Failed to destroy previous Vanta instance', e);
          }
        }

        try {
          vantaInstanceRef.current = window.VANTA.NET({
            el: vantaContainerRef.current,
            mouseControls: true,
            touchControls: true,
            gyroControls: false,
            minHeight: 200.0,
            minWidth: 200.0,
            scale: 1.0,
            scaleMobile: 1.0,
            color: 0x10b981, // light green
            backgroundColor: 0xffffff, // white
            points: 10.0,
            maxDistance: 20.0,
            spacing: 15.0,
            showDots: true,
          });
          clearInterval(checkInterval);
        } catch (err) {
          console.error('Vanta initialization error:', err);
        }
      }
    };

    // Try initiating immediately
    initVanta();

    // Set up polling in case Vanta scripts are still loading asynchronously
    checkInterval = setInterval(initVanta, 100);

    // Handle resize
    const handleResize = () => {
      if (vantaInstanceRef.current && typeof vantaInstanceRef.current.resize === 'function') {
        try {
          vantaInstanceRef.current.resize();
        } catch (e) {
          // ignore
        }
      }
    };

    window.addEventListener('resize', handleResize);

    return () => {
      clearInterval(checkInterval);
      window.removeEventListener('resize', handleResize);
      if (vantaInstanceRef.current) {
        try {
          vantaInstanceRef.current.destroy();
        } catch (e) {
          console.error('Failed to destroy Vanta instance on cleanup', e);
        }
      }
    };
  }, []);

  return (
    <div
      ref={vantaContainerRef}
      id="vanta-background-root"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        overflow: 'hidden',
        pointerEvents: 'none', // Essential so background doesn't block UI element clicks
        zIndex: 0,
      }}
    />
  );
}
