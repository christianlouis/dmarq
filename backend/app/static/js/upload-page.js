const UPLOAD_TIMEOUT_MS = 30000;

function uploadForm() {
    return {
        files: [],
        isUploading: false,
        dragover: false,

        get pendingCount() {
            return this.files.filter((file) => file.status === 'pending').length;
        },

        get successCount() {
            return this.files.filter((file) => file.status === 'success').length;
        },

        get errorCount() {
            return this.files.filter((file) => file.status === 'error').length;
        },

        handleFileSelect(event) {
            this.addFiles(event.target.files);
            event.target.value = '';
        },

        handleDrop(event) {
            this.dragover = false;
            this.addFiles(event.dataTransfer.files);
        },

        addFiles(fileList) {
            const validExtensions = ['.xml', '.zip', '.gz', '.gzip'];
            for (const file of fileList) {
                const dotIndex = file.name.lastIndexOf('.');
                const ext = dotIndex >= 0 ? file.name.slice(dotIndex).toLowerCase() : '';
                if (validExtensions.includes(ext)) {
                    this.files.push({
                        name: file.name,
                        file: file,
                        status: 'pending',
                        message: '',
                    });
                } else {
                    this.files.push({
                        name: file.name,
                        file: file,
                        status: 'error',
                        message: 'Invalid file type. Only XML, ZIP, or GZIP files are supported.',
                    });
                }
            }
            this.uploadPending();
        },

        removeFile(index) {
            this.files.splice(index, 1);
        },

        clearAll() {
            this.files = this.files.filter((file) => file.status === 'uploading');
        },

        async uploadPending() {
            if (this.isUploading) return;
            this.isUploading = true;

            try {
                let entry;
                while ((entry = this.files.find((file) => file.status === 'pending')) !== undefined) {
                    entry.status = 'uploading';
                    entry.message = '';

                    const formData = new FormData();
                    formData.append('file', entry.file);
                    const controller = new AbortController();
                    const timeoutId = window.setTimeout(() => controller.abort(), UPLOAD_TIMEOUT_MS);

                    try {
                        const response = await fetch('/api/v1/reports/upload', {
                            method: 'POST',
                            body: formData,
                            signal: controller.signal,
                        });
                        const data = await response.json();

                        if (response.ok) {
                            const records = data.processed_records || 0;
                            entry.status = 'success';
                            entry.message = `${records} record${records !== 1 ? 's' : ''} for ${data.domain || 'unknown domain'}`;
                        } else {
                            entry.status = 'error';
                            entry.message = data.detail || 'Upload failed';
                        }
                    } catch (error) {
                        entry.status = 'error';
                        entry.message = error.name === 'AbortError'
                            ? 'Upload failed: request timed out'
                            : `Upload failed: ${error.message}`;
                    } finally {
                        window.clearTimeout(timeoutId);
                    }
                }
            } finally {
                this.isUploading = false;
                window.dispatchEvent(new CustomEvent('dmarq:refresh-data'));
            }
        },
    };
}
