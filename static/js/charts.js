/**
 * PromptShield AI — Charts & Visualizations Engine
 * 
 * Implements:
 * 1. Animated High-Precision Risk Speedometer Gauge (Canvas-based)
 * 2. Real-Time Telemetry Risk Distribution Donut Chart (Chart.js)
 */

(function (window) {
  'use strict';

  const PromptCharts = {
    gaugeCanvas: null,
    gaugeCtx: null,
    currentScore: 0,
    targetScore: 0,
    gaugeAnimId: null,
    telemetryChart: null,

    /**
     * Color mapping for risk tiers
     */
    colors: {
      CRITICAL: '#EF4444',
      HIGH: '#F97316',
      MEDIUM: '#F59E0B',
      LOW: '#10B981',
      DEFAULT: '#38BDF8',
      TRACK: '#1E293B',
      SURFACE: '#0B132B'
    },

    /**
     * Initialize the radial speedometer risk gauge
     */
    initGauge: function (canvasId) {
      this.gaugeCanvas = document.getElementById(canvasId);
      if (!this.gaugeCanvas) return;
      this.gaugeCtx = this.gaugeCanvas.getContext('2d');
      this.drawGauge(0, 'LOW');
    },

    /**
     * Animate gauge from current score to target score
     */
    setGaugeScore: function (score, riskLevel) {
      if (!this.gaugeCanvas || !this.gaugeCtx) {
        this.initGauge('riskGaugeCanvas');
      }
      if (!this.gaugeCtx) return;

      if (this.gaugeAnimId) {
        cancelAnimationFrame(this.gaugeAnimId);
      }

      const startScore = this.currentScore;
      const endScore = Math.max(0, Math.min(100, Math.round(score)));
      const startTime = performance.now();
      const duration = 1000; // 1s smooth easing

      const self = this;
      function animate(time) {
        const elapsed = time - startTime;
        const progress = Math.min(1, elapsed / duration);
        // Cubic ease-out
        const ease = 1 - Math.pow(1 - progress, 3);
        const interpolated = startScore + (endScore - startScore) * ease;

        self.currentScore = interpolated;
        self.drawGauge(interpolated, riskLevel);

        if (progress < 1) {
          self.gaugeAnimId = requestAnimationFrame(animate);
        } else {
          self.currentScore = endScore;
          self.drawGauge(endScore, riskLevel);
        }
      }

      this.gaugeAnimId = requestAnimationFrame(animate);
    },

    /**
     * Render the radial arc speedometer gauge on the 2D canvas
     */
    drawGauge: function (score, riskLevel) {
      const canvas = this.gaugeCanvas;
      const ctx = this.gaugeCtx;
      if (!canvas || !ctx) return;

      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      const centerY = height - 15;
      const radius = 80;
      const lineWidth = 16;

      ctx.clearRect(0, 0, width, height);

      // Gauge Arc angles: from -Math.PI to 0 (semi-circle)
      const startAngle = Math.PI;
      const endAngle = 2 * Math.PI;

      // 1. Draw Background Track Arc
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, startAngle, endAngle, false);
      ctx.lineWidth = lineWidth;
      ctx.strokeStyle = this.colors.TRACK;
      ctx.lineCap = 'round';
      ctx.stroke();

      // 2. Draw 4 Qualitative Tier Steps behind the track
      const drawStep = (fromFrac, toFrac, color) => {
        const s = startAngle + fromFrac * Math.PI;
        const e = startAngle + toFrac * Math.PI;
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, s, e, false);
        ctx.lineWidth = lineWidth - 6;
        ctx.strokeStyle = color;
        ctx.lineCap = 'butt';
        ctx.stroke();
      };

      drawStep(0.00, 0.30, 'rgba(16, 185, 129, 0.25)'); // Low (0-30)
      drawStep(0.30, 0.60, 'rgba(245, 158, 11, 0.25)'); // Medium (30-60)
      drawStep(0.60, 0.80, 'rgba(249, 115, 22, 0.25)'); // High (60-80)
      drawStep(0.80, 1.00, 'rgba(239, 68, 68, 0.25)');  // Critical (80-100)

      // 3. Determine Color Gradient for Active Score Arc
      const normalizedLevel = (riskLevel || 'LOW').toUpperCase();
      let activeColor = this.colors.DEFAULT;
      if (normalizedLevel === 'CRITICAL') activeColor = this.colors.CRITICAL;
      else if (normalizedLevel === 'HIGH') activeColor = this.colors.HIGH;
      else if (normalizedLevel === 'MEDIUM') activeColor = this.colors.MEDIUM;
      else if (normalizedLevel === 'LOW') activeColor = this.colors.LOW;

      const scoreFrac = Math.max(0.02, Math.min(1.0, score / 100));
      const scoreAngle = startAngle + scoreFrac * Math.PI;

      // Draw Active Gradient Arc
      const grad = ctx.createLinearGradient(0, centerY, width, centerY);
      grad.addColorStop(0, '#10B981');
      grad.addColorStop(0.35, '#F59E0B');
      grad.addColorStop(0.7, '#F97316');
      grad.addColorStop(1, '#EF4444');

      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, startAngle, scoreAngle, false);
      ctx.lineWidth = lineWidth;
      ctx.strokeStyle = grad;
      ctx.lineCap = 'round';
      ctx.stroke();

      // 4. Draw Radial Needle / Indicator Dot
      const needleAngle = startAngle + scoreFrac * Math.PI;
      const dotX = centerX + (radius) * Math.cos(needleAngle);
      const dotY = centerY + (radius) * Math.sin(needleAngle);

      // Outer Glow Dot
      ctx.beginPath();
      ctx.arc(dotX, dotY, 6, 0, 2 * Math.PI);
      ctx.fillStyle = '#FFFFFF';
      ctx.shadowColor = activeColor;
      ctx.shadowBlur = 12;
      ctx.fill();
      ctx.shadowBlur = 0; // reset shadow
    },

    /**
     * Initialize or Update Chart.js Telemetry Donut Chart
     */
    updateTelemetryChart: function (canvasId, counts) {
      const canvas = document.getElementById(canvasId);
      if (!canvas) return;

      const emptyNotice = document.getElementById('donut-empty-msg');
      const total = (counts.CRITICAL || 0) + (counts.HIGH || 0) + (counts.MEDIUM || 0) + (counts.LOW || 0);

      if (total === 0) {
        if (emptyNotice) emptyNotice.style.display = 'block';
        if (this.telemetryChart) {
          this.telemetryChart.destroy();
          this.telemetryChart = null;
        }
        return;
      }

      if (emptyNotice) emptyNotice.style.display = 'none';

      const dataValues = [
        counts.CRITICAL || 0,
        counts.HIGH || 0,
        counts.MEDIUM || 0,
        counts.LOW || 0
      ];

      const backgroundColors = [
        this.colors.CRITICAL,
        this.colors.HIGH,
        this.colors.MEDIUM,
        this.colors.LOW
      ];

      if (this.telemetryChart) {
        this.telemetryChart.data.datasets[0].data = dataValues;
        this.telemetryChart.update();
        return;
      }

      // Check if Chart is available
      if (typeof Chart === 'undefined') {
        console.warn('Chart.js not loaded yet');
        return;
      }

      const ctx = canvas.getContext('2d');
      this.telemetryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Critical Threat', 'High Risk', 'Medium Risk', 'Low / Safe'],
          datasets: [{
            data: dataValues,
            backgroundColor: backgroundColors,
            borderColor: '#0F172A',
            borderWidth: 3,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#94A3B8',
                font: { family: 'Inter', size: 12 },
                padding: 14,
                usePointStyle: true,
                pointStyle: 'circle'
              }
            },
            tooltip: {
              backgroundColor: '#0F172A',
              titleColor: '#F8FAFC',
              bodyColor: '#CBD5E1',
              borderColor: '#1E293B',
              borderWidth: 1,
              padding: 10,
              boxPadding: 4,
              callbacks: {
                label: function (context) {
                  const label = context.label || '';
                  const val = context.raw || 0;
                  const pct = Math.round((val / total) * 100);
                  return ` ${label}: ${val} (${pct}%)`;
                }
              }
            }
          },
          animation: {
            animateScale: true,
            animateRotate: true,
            duration: 800
          }
        }
      });
    }
  };

  window.PromptCharts = PromptCharts;

})(window);
