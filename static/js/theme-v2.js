/* CyberScan v2 visual layer.
   Builds the decorative 3D artwork (Shield Core canvas, verdict puck,
   isometric scanner stack) and the motion (tilt, reveal, gauge fill, card flip).
   Everything here is presentation only: it never reads or changes form data,
   and every element it creates lives inside an aria-hidden artwork container. */
(function () {
  "use strict";

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var finePointer = window.matchMedia("(hover: hover) and (pointer: fine)").matches;

  function isLight() {
    return document.documentElement.getAttribute("data-theme") === "light";
  }

  function onVisible(el, cb, threshold) {
    if (!("IntersectionObserver" in window)) { cb(); return; }
    var io = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting) return;
      io.disconnect();
      cb();
    }, { threshold: threshold || 0.15 });
    io.observe(el);
  }

  /* ==================================================================
     1. Shield Core: a tiny Canvas-2D 3D engine (perspective projection,
        yaw/pitch rotation, painter's sorting). Same scene as the landing
        example; options come from data-v2-* attributes on the canvas.
     ================================================================== */
  var RING_DEFS = {
    url: { color: "url", label: "URL", tiltX: 1.15, tiltZ: 0.35, speed: 0.42, dashed: false },
    domain: { color: "domain", label: "DOMAIN", tiltX: 1.35, tiltZ: -0.55, speed: -0.3, dashed: true },
    dns: { color: "dns", label: "DNS", tiltX: 0.9, tiltZ: 0.95, speed: 0.24, dashed: false }
  };
  var PALETTE = {
    dark: {
      rose: [251, 113, 133], brand: [139, 26, 61], benign: [52, 211, 153], malicious: [244, 63, 94],
      unchecked: [240, 220, 228], star: [243, 196, 209],
      url: [251, 113, 133], domain: [79, 209, 197], dns: [165, 180, 252]
    },
    light: {
      rose: [194, 51, 95], brand: [139, 26, 61], benign: [5, 150, 105], malicious: [225, 29, 72],
      unchecked: [120, 70, 90], star: [139, 26, 61],
      url: [226, 69, 107], domain: [15, 158, 147], dns: [91, 111, 224]
    }
  };

  function rgba(c, a) { return "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + a + ")"; }

  function cubic(p0, p1, p2, p3, steps, out) {
    for (var i = 1; i <= steps; i++) {
      var t = i / steps, u = 1 - t;
      out.push([
        u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
        u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1]
      ]);
    }
  }

  /* The brand shield path (templates/base.html), extruded into a solid */
  var SHIELD = (function () {
    var K = 3.4, THICK = 15;
    function toModel(px, py) { return [(px - 24) * K, -(py - 28) * K]; }
    var outline2D = [[24, 3], [42, 10], [42, 27]];
    cubic([42, 27], [42, 40], [33, 49], [24, 53], 10, outline2D);
    cubic([24, 53], [15, 49], [6, 40], [6, 27], 10, outline2D);
    outline2D.push([6, 10]);
    var outline = outline2D.map(function (p) { return toModel(p[0], p[1]); });
    var front = outline.map(function (p) { return [p[0], p[1], -THICK]; });
    var back = outline.map(function (p) { return [p[0], p[1], THICK]; });
    var centroid = outline.reduce(function (a, p) {
      return [a[0] + p[0] / outline.length, a[1] + p[1] / outline.length];
    }, [0, 0]);
    var sides = [];
    for (var i = 0; i < outline.length; i++) {
      var a = outline[i], b = outline[(i + 1) % outline.length];
      var dx = b[0] - a[0], dy = b[1] - a[1];
      var len = Math.hypot(dx, dy) || 1;
      var n = [dy / len, -dx / len, 0];
      var mid = [(a[0] + b[0]) / 2 - centroid[0], (a[1] + b[1]) / 2 - centroid[1]];
      if (n[0] * mid[0] + n[1] * mid[1] < 0) n = [-n[0], -n[1], 0];
      sides.push({ pts: [front[i], front[(i + 1) % outline.length], back[(i + 1) % outline.length], back[i]], n: n });
    }
    var check = [[17, 28], [22, 33], [31, 22]].map(function (p) {
      var m = toModel(p[0], p[1]);
      return [m[0], m[1], -THICK - 2];
    });
    var l = [-0.45, 0.65, -0.75], lm = Math.hypot(l[0], l[1], l[2]);
    return { front: front, back: back, sides: sides, check: check, light: [l[0] / lm, l[1] / lm, l[2] / lm] };
  })();

  function ShieldScene(canvas) {
    var ctx = canvas.getContext("2d");
    var host = canvas.closest("[data-v2-scene-host]") || canvas.parentElement;
    var ringKeys = (canvas.getAttribute("data-v2-rings") || "url,domain,dns").split(",");
    var maxPackets = parseInt(canvas.getAttribute("data-v2-packets") || "44", 10);
    var showStars = canvas.getAttribute("data-v2-stars") !== "off";
    var labels = canvas.getAttribute("data-v2-labels") !== "off";
    var radii = ringKeys.length === 1 ? [235] : [215, 250, 285];
    var rings = ringKeys.map(function (k, i) {
      var d = RING_DEFS[k] || RING_DEFS.url;
      return { r: radii[i] || 285, tiltX: d.tiltX, tiltZ: d.tiltZ, speed: d.speed, dashed: d.dashed, color: d.color, label: d.label };
    });

    var W = 0, H = 0, CX = 0, CY = 0, FOCAL = 1, CAM_DIST = 1100;
    var yaw = 0, pitch = -0.3, targetYaw = 0, targetPitch = -0.3;
    var cosY = 1, sinY = 0, cosP = 1, sinP = 0;
    var C = PALETTE.dark;
    var FLOOR_Y = -175, INSPECT_R = 175, SPAWN_R = 720;
    var packets = [], shocks = [], pulses = [], blips = [];
    var flash = { color: C.rose, t: 0 };
    var spawnTimer = 0;
    var stars = [];
    for (var s = 0; s < 110; s++) stars.push({ x: Math.random(), y: Math.random(), d: 0.2 + Math.random() * 0.8, tw: Math.random() * 6 });

    function resize() {
      var rect = canvas.getBoundingClientRect();
      var dpr = Math.min(2, window.devicePixelRatio || 1);
      W = Math.max(1, rect.width); H = Math.max(1, rect.height);
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      CX = W / 2; CY = H * 0.47;
      FOCAL = Math.min(W * 0.95, H) * 1.7;
    }

    function rotate(p) {
      var x = p[0] * cosY + p[2] * sinY;
      var z = -p[0] * sinY + p[2] * cosY;
      var y = p[1];
      return [x, y * cosP - z * sinP, y * sinP + z * cosP];
    }
    function project(r) {
      var k = FOCAL / (r[2] + CAM_DIST);
      return [CX + r[0] * k, CY - r[1] * k, k];
    }
    function ringPoint(ring, t) {
      var x = ring.r * Math.cos(t), z = ring.r * Math.sin(t);
      var y1 = -z * Math.sin(ring.tiltX), z1 = z * Math.cos(ring.tiltX);
      var cz = Math.cos(ring.tiltZ), sz = Math.sin(ring.tiltZ);
      return [x * cz - y1 * sz, x * sz + y1 * cz, z1];
    }
    function poly(pts) {
      ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]);
      for (var i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1]);
      ctx.closePath();
    }

    function spawnPacket() {
      var u = [Math.random() * 2 - 1, (Math.random() * 2 - 1) * 0.7, Math.random() * 2 - 1];
      var m = Math.hypot(u[0], u[1], u[2]) || 1;
      u = [u[0] / m, u[1] / m, u[2] / m];
      if (u[2] < -0.3) u[2] = -u[2];
      var p = [u[0] * SPAWN_R, u[1] * SPAWN_R, u[2] * SPAWN_R];
      var aim = [(Math.random() - 0.5) * 70, (Math.random() - 0.5) * 70, (Math.random() - 0.5) * 70];
      var d = [aim[0] - p[0], aim[1] - p[1], aim[2] - p[2]];
      var dm = Math.hypot(d[0], d[1], d[2]);
      var speed = 150 + Math.random() * 90;
      packets.push({ p: p, v: [d[0] / dm * speed, d[1] / dm * speed, d[2] / dm * speed], state: 0, trail: [], life: 0 });
    }

    function inspect(pk) {
      pk.state = Math.random() < 0.24 ? 2 : 1;
      var dist = Math.hypot(pk.p[0], pk.p[1], pk.p[2]) || 1;
      var n = [pk.p[0] / dist, pk.p[1] / dist, pk.p[2] / dist];
      blips.push({ a: Math.atan2(pk.p[2], pk.p[0]), r: 120 + Math.random() * 140, state: pk.state, t: 1 });
      if (pk.state === 2) {
        var dot = pk.v[0] * n[0] + pk.v[1] * n[1] + pk.v[2] * n[2];
        pk.v = [pk.v[0] - 2 * dot * n[0], pk.v[1] - 2 * dot * n[1], pk.v[2] - 2 * dot * n[2]];
        pk.v = pk.v.map(function (c) { return c * 1.35 + (Math.random() - 0.5) * 60; });
        shocks.push({ p: pk.p.slice(), t: 0 });
        flash = { key: "malicious", t: 1 };
      } else if (flash.t < 0.3) {
        flash = { key: "benign", t: 0.55 };
      }
    }

    function update(dt, time) {
      var idle = reduceMotion ? 0 : Math.sin(time * 0.25) * 0.35;
      yaw += (targetYaw + idle - yaw) * Math.min(1, dt * 3);
      pitch += (targetPitch - pitch) * Math.min(1, dt * 3);
      spawnTimer -= dt;
      if (spawnTimer <= 0 && packets.length < maxPackets) {
        spawnPacket();
        spawnTimer = 0.22 + Math.random() * 0.2;
      }
      for (var i = packets.length - 1; i >= 0; i--) {
        var pk = packets[i];
        pk.life += dt;
        pk.trail.push(pk.p.slice());
        if (pk.trail.length > 7) pk.trail.shift();
        pk.p = [pk.p[0] + pk.v[0] * dt, pk.p[1] + pk.v[1] * dt, pk.p[2] + pk.v[2] * dt];
        var d = Math.hypot(pk.p[0], pk.p[1], pk.p[2]);
        if (pk.state === 0 && d < INSPECT_R) inspect(pk);
        for (var j = 0; j < pulses.length; j++) {
          if (pk.state === 0 && Math.abs(d - pulses[j].r) < 30) inspect(pk);
        }
        if ((pk.state === 1 && d < 45) || d > 980 || pk.life > 14) packets.splice(i, 1);
      }
      shocks.forEach(function (sh) { sh.t += dt * 1.6; });
      shocks = shocks.filter(function (sh) { return sh.t < 1; });
      pulses.forEach(function (p) { p.r += 620 * dt; });
      pulses = pulses.filter(function (p) { return p.r < 820; });
      blips.forEach(function (b) { b.t -= dt * 0.35; });
      blips = blips.filter(function (b) { return b.t > 0; });
      flash.t = Math.max(0, flash.t - dt * 1.8);
    }

    function drawStars(time) {
      if (!showStars) return;
      stars.forEach(function (st) {
        var x = ((st.x + yaw * 0.04 * st.d) % 1 + 1) % 1 * W;
        var a = (0.15 + 0.35 * st.d * (0.6 + 0.4 * Math.sin(time * 1.3 + st.tw))) * (isLight() ? 0.55 : 1);
        ctx.fillStyle = rgba(C.star, a.toFixed(3));
        ctx.fillRect(x, st.y * H, st.d * 1.6, st.d * 1.6);
      });
    }

    function drawFloor(time) {
      var sweep = reduceMotion ? 0.8 : time * 0.9;
      [110, 190, 270].forEach(function (r, k) {
        ctx.beginPath();
        for (var a = 0; a <= 64; a++) {
          var t = a / 64 * Math.PI * 2;
          var pr = project(rotate([r * Math.cos(t), FLOOR_Y, r * Math.sin(t)]));
          if (a === 0) ctx.moveTo(pr[0], pr[1]); else ctx.lineTo(pr[0], pr[1]);
        }
        ctx.strokeStyle = rgba(C.rose, 0.1 + k * 0.03);
        ctx.lineWidth = 1;
        ctx.stroke();
      });
      ctx.strokeStyle = rgba(C.rose, 0.07);
      [[[-290, 0], [290, 0]], [[0, -290], [0, 290]]].forEach(function (ln) {
        var p1 = project(rotate([ln[0][0], FLOOR_Y, ln[0][1]]));
        var p2 = project(rotate([ln[1][0], FLOOR_Y, ln[1][1]]));
        ctx.beginPath(); ctx.moveTo(p1[0], p1[1]); ctx.lineTo(p2[0], p2[1]); ctx.stroke();
      });
      var o = project(rotate([0, FLOOR_Y, 0]));
      var steps = 14, span = 0.7;
      for (var k = 0; k < steps; k++) {
        var a0 = sweep - span * (k / steps), a1 = sweep - span * ((k + 1) / steps);
        var q0 = project(rotate([270 * Math.cos(a0), FLOOR_Y, 270 * Math.sin(a0)]));
        var q1 = project(rotate([270 * Math.cos(a1), FLOOR_Y, 270 * Math.sin(a1)]));
        poly([o, q0, q1]);
        ctx.fillStyle = rgba(C.rose, 0.16 * (1 - k / steps));
        ctx.fill();
      }
      var edge = project(rotate([270 * Math.cos(sweep), FLOOR_Y, 270 * Math.sin(sweep)]));
      ctx.beginPath(); ctx.moveTo(o[0], o[1]); ctx.lineTo(edge[0], edge[1]);
      ctx.strokeStyle = rgba(C.rose, 0.55); ctx.lineWidth = 1.4; ctx.stroke();
      blips.forEach(function (b) {
        var col = b.state === 2 ? C.malicious : C.benign;
        var pb = project(rotate([b.r * Math.cos(b.a), FLOOR_Y, b.r * Math.sin(b.a)]));
        ctx.beginPath(); ctx.ellipse(pb[0], pb[1], 4 * pb[2] * 1.6, 2 * pb[2] * 1.6, 0, 0, Math.PI * 2);
        ctx.fillStyle = rgba(col, 0.75 * b.t); ctx.fill();
        ctx.beginPath(); ctx.ellipse(pb[0], pb[1], 12 * pb[2] * (2 - b.t), 5 * pb[2] * (2 - b.t), 0, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(col, 0.35 * b.t); ctx.lineWidth = 1; ctx.stroke();
      });
    }

    function drawRings(time, wantBack) {
      rings.forEach(function (ring) {
        var col = C[ring.color];
        var N = 120, prev = null;
        for (var i = 0; i <= N; i++) {
          var r3 = rotate(ringPoint(ring, i / N * Math.PI * 2));
          var p = project(r3);
          if (prev) {
            var isBack = (r3[2] + prev.z) / 2 > 0;
            if (isBack === wantBack && !(ring.dashed && i % 3 === 0)) {
              ctx.beginPath(); ctx.moveTo(prev.x, prev.y); ctx.lineTo(p[0], p[1]);
              ctx.strokeStyle = rgba(col, isBack ? 0.22 : 0.6);
              ctx.lineWidth = isBack ? 1 : 1.6;
              ctx.stroke();
            }
          }
          prev = { x: p[0], y: p[1], z: r3[2] };
        }
        var tNode = (reduceMotion ? 0.6 : time * ring.speed) + ring.r;
        var n3 = rotate(ringPoint(ring, tNode));
        if ((n3[2] > 0) !== wantBack) return;
        var np = project(n3);
        var size = 5.5 * np[2] * 1.4;
        var g = ctx.createRadialGradient(np[0], np[1], 0, np[0], np[1], size * 4);
        g.addColorStop(0, rgba(col, 0.9)); g.addColorStop(1, rgba(col, 0));
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(np[0], np[1], size * 4, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = isLight() ? rgba(col, 1) : "#fff";
        ctx.beginPath(); ctx.arc(np[0], np[1], size * 0.7, 0, Math.PI * 2); ctx.fill();
        if (labels) {
          ctx.font = "600 " + Math.max(9, 10.5 * np[2] * 1.3).toFixed(1) + "px 'JetBrains Mono', monospace";
          ctx.fillStyle = rgba(col, wantBack ? 0.5 : 0.95);
          ctx.fillText(ring.label, np[0] + size + 6, np[1] - size - 4);
        }
      });
    }

    function drawPackets(wantBack) {
      packets.forEach(function (pk) {
        var r3 = rotate(pk.p);
        if ((r3[2] > 0) !== wantBack) return;
        var col = pk.state === 2 ? C.malicious : pk.state === 1 ? C.benign : C.unchecked;
        var p = project(r3);
        if (pk.trail.length > 1) {
          ctx.beginPath();
          pk.trail.forEach(function (tp, k) {
            var q = project(rotate(tp));
            if (k === 0) ctx.moveTo(q[0], q[1]); else ctx.lineTo(q[0], q[1]);
          });
          ctx.lineTo(p[0], p[1]);
          ctx.strokeStyle = rgba(col, wantBack ? 0.2 : 0.45);
          ctx.lineWidth = Math.max(0.6, 1.6 * p[2]);
          ctx.stroke();
        }
        var rad = Math.max(1.2, 3.2 * p[2] * 1.3);
        if (pk.state !== 0) {
          ctx.fillStyle = rgba(col, 0.25);
          ctx.beginPath(); ctx.arc(p[0], p[1], rad * 3, 0, Math.PI * 2); ctx.fill();
        }
        ctx.fillStyle = rgba(col, wantBack ? 0.6 : 1);
        ctx.beginPath(); ctx.arc(p[0], p[1], rad, 0, Math.PI * 2); ctx.fill();
      });
    }

    function drawShield() {
      var L = SHIELD.light;
      var flashCol = flash.key ? C[flash.key] : C.rose;
      var faces = [];
      SHIELD.sides.forEach(function (f) {
        var rn = rotate(f.n);
        if (rn[2] > 0.02) return;
        var rp = f.pts.map(rotate);
        var z = (rp[0][2] + rp[1][2] + rp[2][2] + rp[3][2]) / 4;
        var lit = Math.max(0, rn[0] * L[0] + rn[1] * L[1] + rn[2] * L[2]);
        faces.push({ z: z, pts: rp.map(project), kind: "side", lit: lit });
      });
      var fn = rotate([0, 0, -1]);
      var frontVisible = fn[2] < 0;
      var capPts = (frontVisible ? SHIELD.front : SHIELD.back).map(rotate);
      var capZ = capPts.reduce(function (a, p) { return a + p[2]; }, 0) / capPts.length;
      faces.push({ z: capZ, pts: capPts.map(project), kind: "cap" });
      faces.sort(function (a, b) { return b.z - a.z; });

      faces.forEach(function (f) {
        poly(f.pts);
        if (f.kind === "side") {
          var k = 0.28 + 0.72 * f.lit;
          ctx.fillStyle = "rgb(" + Math.round(C.brand[0] * k + 20) + "," + Math.round(C.brand[1] * k + 3) + "," + Math.round(C.brand[2] * k + 8) + ")";
          ctx.fill();
          ctx.strokeStyle = rgba(C.rose, 0.18 + 0.25 * f.lit);
          ctx.lineWidth = 0.8;
          ctx.stroke();
          return;
        }
        var ys = f.pts.map(function (p) { return p[1]; });
        var xs = f.pts.map(function (p) { return p[0]; });
        var top = Math.min.apply(null, ys), bot = Math.max.apply(null, ys);
        var left = Math.min.apply(null, xs), right = Math.max.apply(null, xs);
        var g = ctx.createLinearGradient(0, top, 0, bot);
        g.addColorStop(0, "rgba(194,51,95,0.96)");
        g.addColorStop(0.55, "rgba(110,18,46,0.96)");
        g.addColorStop(1, "rgba(44,5,15,0.98)");
        ctx.fillStyle = g; ctx.fill();
        ctx.save();
        poly(f.pts); ctx.clip();
        var sx = left + (right - left) * (0.5 + Math.sin(yaw * 2.2) * 0.6);
        var sheen = ctx.createLinearGradient(sx - 60, top, sx + 60, bot);
        sheen.addColorStop(0, "rgba(255,255,255,0)");
        sheen.addColorStop(0.5, "rgba(255,255,255,0.16)");
        sheen.addColorStop(1, "rgba(255,255,255,0)");
        ctx.fillStyle = sheen; ctx.fillRect(left, top, right - left, bot - top);
        if (flash.t > 0) { ctx.fillStyle = rgba(flashCol, 0.35 * flash.t); ctx.fillRect(left, top, right - left, bot - top); }
        ctx.restore();
        poly(f.pts);
        ctx.shadowColor = rgba(flash.t > 0 ? flashCol : C.rose, 0.9);
        ctx.shadowBlur = 18 + 14 * flash.t;
        ctx.strokeStyle = rgba(flash.t > 0 ? flashCol : PALETTE.dark.rose, 0.95);
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.shadowBlur = 0;
      });

      if (frontVisible) {
        var cp = SHIELD.check.map(function (p) { return project(rotate(p)); });
        ctx.beginPath(); ctx.moveTo(cp[0][0], cp[0][1]); ctx.lineTo(cp[1][0], cp[1][1]); ctx.lineTo(cp[2][0], cp[2][1]);
        ctx.lineCap = "round"; ctx.lineJoin = "round";
        ctx.strokeStyle = flash.t > 0.2 ? rgba(flashCol, 1) : "rgba(255,255,255,0.95)";
        ctx.lineWidth = 7 * cp[0][2];
        ctx.shadowColor = "rgba(255,255,255,0.6)"; ctx.shadowBlur = 10;
        ctx.stroke(); ctx.shadowBlur = 0;
      }
    }

    function drawEffects() {
      var o = project(rotate([0, 0, 0]));
      pulses.forEach(function (p) {
        ctx.beginPath(); ctx.arc(o[0], o[1], p.r * o[2], 0, Math.PI * 2);
        ctx.strokeStyle = rgba(C.rose, Math.max(0, 0.6 * (1 - p.r / 820)));
        ctx.lineWidth = 2; ctx.stroke();
      });
      shocks.forEach(function (sh) {
        var p = project(rotate(sh.p));
        ctx.beginPath(); ctx.arc(p[0], p[1], (6 + 34 * sh.t) * p[2] * 1.4, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(C.malicious, 0.8 * (1 - sh.t)); ctx.lineWidth = 2; ctx.stroke();
      });
    }

    function render(time) {
      C = isLight() ? PALETTE.light : PALETTE.dark;
      cosY = Math.cos(yaw); sinY = Math.sin(yaw); cosP = Math.cos(pitch); sinP = Math.sin(pitch);
      ctx.clearRect(0, 0, W, H);
      drawStars(time);
      drawFloor(time);
      drawRings(time, true);
      drawPackets(true);
      drawShield();
      drawPackets(false);
      drawRings(time, false);
      drawEffects();
    }

    var last = 0, running = false, rafId = 0, clock = 0;
    function frame(now) {
      var dt = Math.min(0.05, (now - last) / 1000 || 0.016);
      last = now;
      clock += dt;
      update(dt, clock);
      render(clock);
      if (running) rafId = requestAnimationFrame(frame);
    }
    function start() {
      if (running || reduceMotion) return;
      running = true; last = performance.now(); rafId = requestAnimationFrame(frame);
    }
    function stop() { running = false; cancelAnimationFrame(rafId); }

    host.addEventListener("pointermove", function (e) {
      var r = host.getBoundingClientRect();
      targetYaw = ((e.clientX - r.left) / r.width - 0.5) * 1.4;
      targetPitch = -0.3 + ((e.clientY - r.top) / r.height - 0.5) * 0.35;
    });
    host.addEventListener("pointerleave", function () { targetYaw = 0; targetPitch = -0.3; });
    canvas.addEventListener("click", function () {
      pulses.push({ r: 20 });
      if (reduceMotion) { for (var k = 0; k < 40; k++) update(1 / 30, clock); render(clock); }
    });

    resize();
    if (window.ResizeObserver) {
      new ResizeObserver(function () { resize(); if (!running) render(clock); }).observe(canvas);
    } else {
      window.addEventListener("resize", resize);
    }
    /* Theme switch on the Settings page repaints a paused scene */
    new MutationObserver(function () { if (!running) render(clock); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    if (reduceMotion) {
      for (var k = 0; k < 360; k++) update(1 / 60, k / 60);
      render(6);
    } else {
      if ("IntersectionObserver" in window) {
        new IntersectionObserver(function (entries) {
          if (entries[0].isIntersecting) start(); else stop();
        }).observe(canvas);
      } else {
        start();
      }
      document.addEventListener("visibilitychange", function () { if (document.hidden) stop(); else start(); });
    }
    var stage = canvas.closest(".v2-scene");
    if (stage) stage.classList.add("is-live");
  }

  function initScenes() {
    document.querySelectorAll("canvas[data-v2-scene]").forEach(function (canvas) {
      if (!canvas.getContext) return;
      try { ShieldScene(canvas); } catch (e) { /* keep the static SVG fallback */ }
    });
  }

  /* ==================================================================
     2. Verdict puck: 26 stacked discs give it thickness, the top face is
        a conic gauge of the real confidence (set in the template).
     ================================================================== */
  function initPucks() {
    document.querySelectorAll(".v2-puck").forEach(function (puck) {
      for (var i = 0; i < 26; i++) {
        var layer = document.createElement("div");
        layer.className = "v2-puck-layer";
        layer.style.transform = "translateZ(" + i + "px)";
        puck.appendChild(layer);
      }
      var top = document.createElement("div");
      top.className = "v2-puck-top";
      var glyph = document.createElement("span");
      glyph.className = "v2-puck-glyph";
      glyph.textContent = puck.getAttribute("data-v2-glyph") || "";
      top.appendChild(glyph);
      puck.appendChild(top);
      if (!reduceMotion) {
        puck.classList.add("is-waiting");
        // The lifted puck is clipped by its stage, so watch the stage instead.
        onVisible(puck.closest(".v2-verdict-art") || puck, function () {
          puck.classList.remove("is-waiting");
          puck.classList.add("is-dropping");
        }, 0.3);
      }
    });
  }

  /* ==================================================================
     3. Isometric scanner stack (Sign in): edge layers under each tile,
        and the stack leans toward the pointer.
     ================================================================== */
  function initIso() {
    document.querySelectorAll(".v2-iso-tile").forEach(function (tile) {
      for (var k = 1; k <= 10; k++) {
        var layer = document.createElement("i");
        layer.style.transform = "translateZ(" + (-k) + "px)";
        layer.style.filter = "brightness(" + (1 - k * 0.04) + ")";
        tile.insertBefore(layer, tile.firstChild);
      }
    });
    if (reduceMotion || !finePointer) return;
    var iso = document.querySelector(".v2-iso");
    if (!iso) return;
    document.addEventListener("pointermove", function (e) {
      var x = e.clientX / window.innerWidth - 0.5, y = e.clientY / window.innerHeight - 0.5;
      iso.style.setProperty("--v2-iso-rx", (58 - y * 10).toFixed(2) + "deg");
      iso.style.setProperty("--v2-iso-rz", (-42 + x * 16).toFixed(2) + "deg");
    });
  }

  /* ==================================================================
     4. Gauge rings fill from 0 to the real value when they scroll in
     ================================================================== */
  function initRings() {
    document.querySelectorAll(".v2-ring").forEach(function (ring) {
      if (reduceMotion) { ring.classList.add("is-in"); return; }
      onVisible(ring, function () { ring.classList.add("is-in"); }, 0.4);
    });
  }

  /* ==================================================================
     5. Tilt toward the pointer (cards with depth layers)
     ================================================================== */
  var TILT_SELECTOR = [
    ".home-elite .elite-svc",
    ".home-elite .elite-stat",
    ".metric-card",
    ".domain-info-card",
    ".feature-chip",
    ".auth-elite-card"
  ].join(",");

  function initTilt() {
    if (!finePointer || reduceMotion) return;
    document.querySelectorAll(TILT_SELECTOR).forEach(function (el) {
      var max = el.classList.contains("auth-elite-card") ? 4 : 9;
      el.classList.add("v2-tilt");
      el.addEventListener("pointermove", function (e) {
        var r = el.getBoundingClientRect();
        if (!r.width || !r.height) return;
        var px = (e.clientX - r.left) / r.width;
        var py = (e.clientY - r.top) / r.height;
        el.classList.add("is-tilting");
        el.style.setProperty("--ry", ((px - 0.5) * 2 * max).toFixed(2) + "deg");
        el.style.setProperty("--rx", ((0.5 - py) * 2 * max).toFixed(2) + "deg");
        el.style.setProperty("--mx", (px * 100).toFixed(1) + "%");
        el.style.setProperty("--my", (py * 100).toFixed(1) + "%");
      });
      el.addEventListener("pointerleave", function () {
        el.classList.remove("is-tilting");
        el.style.setProperty("--rx", "0deg");
        el.style.setProperty("--ry", "0deg");
      });
    });
  }

  /* ==================================================================
     6. Reveal on scroll. Things already on screen are left alone so
        nothing visible ever blinks.
     ================================================================== */
  var REVEAL_SELECTOR = [
    ".panel",
    ".metric-card",
    ".feature-chip",
    ".dns-examples",
    ".history-table-wrap",
    ".home-elite .elite-section-head",
    ".home-elite .elite-svc",
    ".home-elite .elite-steps",
    ".home-elite .elite-stat",
    ".home-elite .elite-table-wrap"
  ].join(",");

  function initReveal() {
    if (reduceMotion || !("IntersectionObserver" in window)) return;
    var fold = window.innerHeight;
    var pending = [];
    document.querySelectorAll(REVEAL_SELECTOR).forEach(function (el) {
      if (el.parentElement && el.parentElement.closest("[data-v2-reveal]")) return;
      var r = el.getBoundingClientRect();
      if (!r.width && !r.height) return;
      if (r.top < fold - 40) return;
      el.setAttribute("data-v2-reveal", "pending");
      pending.push(el);
    });
    if (!pending.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        io.unobserve(entry.target);
        entry.target.setAttribute("data-v2-reveal", "shown");
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    pending.forEach(function (el) { io.observe(el); });
  }

  /* ==================================================================
     7. Sign in / Create account: the card swings round like the flip
        card in the example whenever the visible form changes.
     ================================================================== */
  function initAuthFlip() {
    var card = document.querySelector(".auth-elite-card");
    if (!card || reduceMotion) return;
    var activeTab = document.querySelector(".auth-elite-tabs button.active");
    var current = activeTab ? activeTab.getAttribute("data-auth-tab") : "login";
    document.querySelectorAll("[data-auth-tab]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var next = btn.getAttribute("data-auth-tab");
        if (next === current) return;
        current = next;
        card.classList.remove("v2-flip");
        void card.offsetWidth;
        card.classList.add("v2-flip");
      });
    });
    card.addEventListener("animationend", function (e) {
      if (e.animationName === "v2CardFlip") card.classList.remove("v2-flip");
    });
  }

  function init() {
    initScenes();
    initPucks();
    initIso();
    initRings();
    initTilt();
    initReveal();
    initAuthFlip();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
