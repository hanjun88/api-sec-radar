import * as THREE from 'three';
const MAX_DELTA_SECONDS = 0.1;
export class SceneManager {
    constructor(config) {
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.elapsed = 0;
        this.updateCallbacks = [];
        this.rafId = null;
        this.disposed = false;
        this.mounted = false;
        this.paused = false;
        this.contextLost = false;
        this.config = {
            pixelRatio: 1,
            antialias: true,
            alpha: false,
            cameraFov: 50,
            cameraNear: 0.1,
            cameraFar: 100,
            cameraPosition: [0, 6, 8],
            ...config,
        };
        this.clock = new THREE.Clock();
        this.boundHandleResize = this.handleResize.bind(this);
        this.boundHandleContextLost = this.handleContextLost.bind(this);
        this.boundHandleContextRestored = this.handleContextRestored.bind(this);
    }
    mount() {
        if (this.mounted || this.disposed)
            return;
        this.scene = new THREE.Scene();
        this.scene.fog = new THREE.FogExp2(0x0a0e17, 0.04);
        const { width, height, cameraFov, cameraNear, cameraFar, cameraPosition } = this.config;
        this.camera = new THREE.PerspectiveCamera(cameraFov, width / height, cameraNear, cameraFar);
        this.camera.position.set(cameraPosition[0], cameraPosition[1], cameraPosition[2]);
        this.camera.lookAt(0, 0, 0);
        this.renderer = new THREE.WebGLRenderer({
            canvas: this.config.canvas,
            antialias: this.config.antialias,
            alpha: this.config.alpha,
        });
        this.renderer.setPixelRatio(this.config.pixelRatio);
        this.renderer.setSize(width, height, false);
        this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
        this.renderer.toneMappingExposure = 1.2;
        const ambient = new THREE.AmbientLight(0x404060, 0.6);
        this.scene.add(ambient);
        const dirLight = new THREE.DirectionalLight(0x88aaff, 0.8);
        dirLight.position.set(5, 10, 5);
        this.scene.add(dirLight);
        const pointLight = new THREE.PointLight(0x00ff88, 0.5, 15);
        pointLight.position.set(0, 2, 0);
        this.scene.add(pointLight);
        this.config.canvas.addEventListener('webglcontextlost', this.boundHandleContextLost);
        this.config.canvas.addEventListener('webglcontextrestored', this.boundHandleContextRestored);
        window.addEventListener('resize', this.boundHandleResize);
        this.mounted = true;
    }
    start() {
        if (!this.mounted || this.disposed || this.rafId !== null)
            return;
        this.clock.start();
        this.paused = false;
        this.loop();
    }
    pause() {
        this.paused = true;
    }
    resume() {
        if (!this.mounted || this.disposed)
            return;
        this.paused = false;
        if (this.rafId === null) {
            this.loop();
        }
    }
    loop() {
        if (this.disposed || this.contextLost)
            return;
        this.rafId = requestAnimationFrame(() => this.loop());
        if (this.paused)
            return;
        const delta = Math.min(this.clock.getDelta(), MAX_DELTA_SECONDS);
        this.elapsed += delta;
        for (const cb of this.updateCallbacks) {
            cb(delta, this.elapsed);
        }
        if (this.renderer && this.scene && this.camera) {
            this.renderer.render(this.scene, this.camera);
        }
    }
    onUpdate(callback) {
        this.updateCallbacks.push(callback);
        return () => {
            this.updateCallbacks = this.updateCallbacks.filter((cb) => cb !== callback);
        };
    }
    resize(width, height) {
        if (!this.camera || !this.renderer)
            return;
        this.camera.aspect = width / height;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(width, height, false);
    }
    computeMVP(modelMatrix) {
        if (!this.camera || !this.mounted) {
            return new THREE.Matrix4().identity();
        }
        this.camera.updateMatrixWorld(true);
        const view = this.camera.matrixWorldInverse.clone();
        const proj = this.camera.projectionMatrix.clone();
        const model = modelMatrix ? modelMatrix.clone() : new THREE.Matrix4().identity();
        return new THREE.Matrix4().multiplyMatrices(proj, view).multiply(model);
    }
    getScene() {
        return this.scene;
    }
    getCamera() {
        return this.camera;
    }
    getRenderer() {
        return this.renderer;
    }
    getStats() {
        if (!this.renderer) {
            return { drawCalls: 0, triangles: 0 };
        }
        const info = this.renderer.info;
        return {
            drawCalls: info?.render?.calls ?? 0,
            triangles: info?.render?.triangles ?? 0,
        };
    }
    handleResize() {
        this.resize(window.innerWidth, window.innerHeight);
    }
    handleContextLost(event) {
        event.preventDefault();
        this.contextLost = true;
        if (this.rafId !== null) {
            cancelAnimationFrame(this.rafId);
            this.rafId = null;
        }
    }
    handleContextRestored() {
        this.contextLost = false;
        if (this.renderer) {
            this.renderer.dispose();
            this.renderer = null;
        }
        this.renderer = new THREE.WebGLRenderer({
            canvas: this.config.canvas,
            antialias: this.config.antialias,
            alpha: this.config.alpha,
        });
        this.renderer.setPixelRatio(this.config.pixelRatio);
        this.renderer.setSize(this.config.width, this.config.height, false);
        this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
        this.renderer.toneMappingExposure = 1.2;
        if (!this.paused) {
            this.loop();
        }
    }
    disposeObject3D(obj) {
        const mesh = obj;
        if (mesh.geometry) {
            mesh.geometry.dispose();
        }
        if (mesh.material) {
            if (Array.isArray(mesh.material)) {
                mesh.material.forEach((mat) => this.disposeMaterial(mat));
            }
            else {
                this.disposeMaterial(mesh.material);
            }
        }
        obj.children.forEach((child) => this.disposeObject3D(child));
    }
    disposeMaterial(material) {
        const mat = material;
        const textureKeys = [
            'map', 'normalMap', 'roughnessMap', 'metalnessMap',
            'aoMap', 'emissiveMap', 'alphaMap', 'envMap',
            'bumpMap', 'displacementMap', 'lightMap',
        ];
        for (const key of textureKeys) {
            if (mat[key] && typeof mat[key].dispose === 'function') {
                mat[key].dispose();
            }
        }
        material.dispose();
    }
    dispose() {
        if (this.disposed)
            return;
        this.disposed = true;
        if (this.rafId !== null) {
            cancelAnimationFrame(this.rafId);
            this.rafId = null;
        }
        this.config.canvas.removeEventListener('webglcontextlost', this.boundHandleContextLost);
        this.config.canvas.removeEventListener('webglcontextrestored', this.boundHandleContextRestored);
        window.removeEventListener('resize', this.boundHandleResize);
        if (this.scene) {
            this.scene.children.forEach((child) => this.disposeObject3D(child));
        }
        if (this.renderer) {
            this.renderer.dispose();
            this.renderer = null;
        }
        this.scene = null;
        this.camera = null;
        this.updateCallbacks = [];
        this.mounted = false;
    }
}
