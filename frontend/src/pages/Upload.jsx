import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, File, AlertCircle, CheckCircle2, Shield } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';

export function Upload() {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const inputRef = useRef(null);
  const navigate = useNavigate();

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (selectedFile) => {
    // Basic frontend validation mock
    if (!selectedFile.name.endsWith('.apk')) {
      alert("Only .apk files are supported.");
      return;
    }
    setFile(selectedFile);
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    
    try {
      const formData = new FormData();
      formData.append("file", file);
      
      const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
      const response = await fetch(`${API_BASE}/api/v1/apks/upload`, {
        method: "POST",
        body: formData,
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Upload failed");
      }
      
      const data = await response.json();
      setUploading(false);
      navigate(`/analysis/${data.sample_id}`);
    } catch (error) {
      console.error("Upload Error:", error);
      alert(error.message);
      setUploading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 mt-10">
      <div className="text-center space-y-2 mb-8">
        <div className="inline-flex items-center justify-center p-3 bg-primary/10 rounded-full mb-4">
          <Shield className="w-8 h-8 text-primary" />
        </div>
        <h1 className="text-3xl font-bold tracking-tight">APK Security Investigation</h1>
        <p className="text-textMuted max-w-xl mx-auto">
          Upload an Android application (.apk) to initiate the automated threat analysis pipeline.
        </p>
      </div>

      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          <div 
            className={`relative p-12 flex flex-col items-center justify-center border-2 border-dashed transition-all duration-300 ${dragActive ? 'border-primary bg-primary/5' : 'border-borderSubtle bg-surface/30'} ${file ? 'pb-8 pt-8' : ''}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".apk"
              className="hidden"
              onChange={handleChange}
            />

            {!file ? (
              <>
                <UploadCloud className={`w-16 h-16 mb-6 transition-colors ${dragActive ? 'text-primary' : 'text-textMuted'}`} />
                <h3 className="text-xl font-semibold mb-2">Drag & Drop APK File</h3>
                <p className="text-textMuted mb-6 text-sm text-center max-w-sm">
                  Supported formats: .apk (Max file size: 100MB)
                </p>
                <Button onClick={() => inputRef.current?.click()} size="lg">
                  Browse Files
                </Button>
              </>
            ) : (
              <div className="w-full max-w-md bg-surface border border-borderSubtle rounded-lg p-4 flex items-center justify-between">
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className="p-2 bg-primary/20 rounded-md">
                    <File className="w-6 h-6 text-primary" />
                  </div>
                  <div className="overflow-hidden">
                    <p className="font-medium truncate">{file.name}</p>
                    <p className="text-xs text-textMuted">{(file.size / (1024 * 1024)).toFixed(2)} MB</p>
                  </div>
                </div>
                <button 
                  onClick={() => setFile(null)}
                  className="text-textMuted hover:text-danger p-2 transition-colors"
                >
                  <AlertCircle className="w-5 h-5" />
                </button>
              </div>
            )}
          </div>
          
          {file && (
            <div className="p-6 bg-surfaceHighlight border-t border-borderSubtle flex justify-end">
              <Button 
                onClick={handleUpload} 
                disabled={uploading}
                className="w-full sm:w-auto"
              >
                {uploading ? (
                  <>
                    <span className="animate-spin mr-2 border-2 border-current border-t-transparent rounded-full w-4 h-4"></span>
                    Initializing Pipeline...
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4 mr-2" />
                    Start Analysis
                  </>
                )}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-12 text-center text-sm text-textMuted">
        <div className="p-4 border border-borderSubtle rounded-lg bg-surface/30">
          <CheckCircle2 className="w-5 h-5 mx-auto mb-2 text-success" />
          <p>Static & Dynamic Analysis</p>
        </div>
        <div className="p-4 border border-borderSubtle rounded-lg bg-surface/30">
          <CheckCircle2 className="w-5 h-5 mx-auto mb-2 text-success" />
          <p>Malware DNA Matching</p>
        </div>
        <div className="p-4 border border-borderSubtle rounded-lg bg-surface/30">
          <CheckCircle2 className="w-5 h-5 mx-auto mb-2 text-success" />
          <p>AI Agent Investigation</p>
        </div>
      </div>
    </div>
  );
}
