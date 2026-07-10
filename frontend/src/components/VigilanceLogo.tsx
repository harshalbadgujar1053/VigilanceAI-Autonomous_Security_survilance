import React from 'react';

interface VigilanceLogoProps {
  className?: string;
  size?: number;
}

export default function VigilanceLogo({ className = '', size = 32 }: VigilanceLogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 1000 1000"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`vigilance-logo ${className}`}
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      <defs>
        {/* Glow Filters */}
        <filter id="logo-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="25" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        
        <filter id="subtle-glow" x="-10%" y="-10%" width="120%" height="120%">
          <feGaussianBlur stdDeviation="8" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        {/* Ribbon Gradients */}
        <linearGradient id="leftRibbonGrad" x1="200" y1="200" x2="500" y2="800" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" /> {/* Light blue */}
          <stop offset="50%" stopColor="#2563eb" /> {/* Vivid blue */}
          <stop offset="100%" stopColor="#4f46e5" /> {/* Indigo */}
        </linearGradient>

        <linearGradient id="rightRibbonGrad" x1="500" y1="800" x2="800" y2="250" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#4f46e5" /> {/* Indigo */}
          <stop offset="40%" stopColor="#0284c7" /> {/* Blue-cyan */}
          <stop offset="75%" stopColor="#0d9488" /> {/* Teal */}
          <stop offset="100%" stopColor="#10b981" /> {/* Emerald/Mint green */}
        </linearGradient>

        <linearGradient id="globeOutlineGrad" x1="100" y1="100" x2="900" y2="900" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
          <stop offset="50%" stopColor="#0891b2" stopOpacity="0.1" />
          <stop offset="100%" stopColor="#10b981" stopOpacity="0.4" />
        </linearGradient>

        <radialGradient id="globeSphereGrad" cx="500" cy="500" r="400" fx="500" fy="500" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#082f49" stopOpacity="0.8" />
          <stop offset="70%" stopColor="#0f172a" stopOpacity="0.95" />
          <stop offset="100%" stopColor="#030712" stopOpacity="1" />
        </radialGradient>
      </defs>

      {/* 1. THE 'V' FOREGROUND RIBBON (3D LAYERED) */}
      <g filter="url(#logo-glow)">
        {/* Left Arm of V (Grows thicker near bottom bend) */}
        <path
          d="M 230 220 
             C 170 340, 310 650, 460 760 
             C 490 782, 510 782, 540 760
             C 570 738, 640 620, 700 500"
          fill="none"
          stroke="url(#leftRibbonGrad)"
          strokeWidth="110"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Right Arm of V (Graceful loop at the top right) */}
        {/* We overlap this loop to create the elegant folding effect shown in the logo */}
        <path
          d="M 640 580
             C 690 480, 770 260, 790 220
             C 840 120, 960 210, 860 360
             C 780 480, 690 580, 640 620"
          fill="none"
          stroke="url(#rightRibbonGrad)"
          strokeWidth="100"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </g>

      {/* 2. FOUR-POINT STAR SPARKLE */}
      <path
        d="M 870 790 
           Q 870 830 910 830 
           Q 870 830 870 870 
           Q 870 830 830 830 
           Q 870 830 870 790 Z"
        fill="#ffffff"
        filter="url(#subtle-glow)"
      />
    </svg>
  );
}
