import React, { createContext, useContext, useState, useEffect } from 'react'

const translations = {
  id: {
    common: {
      appName: 'Faycryptor',
      loading: 'Memuat...',
      save: 'Simpan',
      cancel: 'Batal',
      delete: 'Hapus',
      close: 'Tutup',
      search: 'Cari',
      prev: 'Sebelumnya',
      next: 'Selanjutnya',
      pageOf: 'Halaman {current} dari {total}',
      actions: 'Aksi',
      status: 'Status',
      date: 'Tanggal',
      author: 'Author',
      algorithm: 'Algoritma',
      fileName: 'Nama File',
      success: 'Berhasil',
      error: 'Terjadi Kesalahan',
      confirm: 'Konfirmasi'
    },
    nav: {
      overview: 'Ikhtisar',
      home: 'Beranda',
      fileOps: 'Operasi File',
      encrypt: 'Enkripsi',
      file: 'Dekripsi File',
      keys: 'Kunci Vault',
      collaboration: 'Kolaborasi',
      workspace: 'Workspace',
      general: 'Umum',
      settings: 'Pengaturan',
      about: 'Tentang',
      personal: 'Personal',
      createOrg: '+ Buat Organisasi...',
      vaultConnected: 'Vault terhubung'
    },
    home: {
      welcome: 'Selamat Datang di Faycryptor',
      subtitle: 'Sistem enkripsi file mandiri berstandar militer dengan sinkronisasi Web Vault.',
      quickActions: 'Aksi Cepat',
      encryptCardTitle: 'Enkripsi File',
      encryptCardDesc: 'Amankan file lokal dengan AES-256 atau FayCipher.',
      decryptCardTitle: 'Dekripsi File',
      decryptCardDesc: 'Buka & lihat file terenkripsi dari vault atau folder lokal.',
      workspaceCardTitle: 'Workspace',
      workspaceCardDesc: 'Kelola organisasi & koneksi berbagi file.',
      recentActivity: 'Aktivitas Terbaru',
      noActivity: 'Belum ada riwayat aktivitas enkripsi/dekripsi.',
      statsTotal: 'Total File Terproteksi',
      statsDecrypted: 'File Terdekripsi',
      statsConnections: 'Koneksi Terhubung'
    },
    encrypt: {
      title: 'Enkripsi File & Folder',
      selectFolder: 'Pilih Folder atau File',
      browseBtn: 'Pilih File...',
      algorithm: 'Algoritma Enkripsi',
      passwordOptional: 'Password Enkripsi (Opsional)',
      passwordPlaceholder: 'Masukkan password proteksi...',
      vaultStore: 'Simpan salinan terenkripsi ke Web Vault',
      encryptBtn: 'Mulai Enkripsi',
      encrypting: 'Sedang Mengenkrpsi...',
      successMsg: 'File berhasil dienkripsi dan diamankan!',
      errorMsg: 'Gagal mengenkripsi file.'
    },
    decrypt: {
      title: 'Daftar File & Dekripsi',
      filterLabel: 'Filter:',
      filterAll: 'Semua File',
      filterEncrypted: 'Terenkripsi',
      filterDecrypted: 'Terdekripsi',
      filterMine: 'Milik Saya',
      filterOrg: 'Dari Organisasi',
      filterConnections: 'Dari Koneksi',
      searchPlaceholder: 'Cari nama, path, author...',
      statusEncrypted: '🔒 Terenkripsi',
      statusDecrypted: '✓ Terdekripsi',
      btnDecrypt: 'Decrypt',
      btnOpen: 'Buka',
      btnDelete: 'Hapus',
      emptyVault: 'Belum ada file di vault. Enkripsi file terlebih dahulu.',
      noMatch: 'Tidak ada file yang cocok dengan filter.',
      modalTitle: 'Dekripsi File Vault',
      modalDesc: 'Masukkan password enkripsi untuk membuka file ini:',
      passPlaceholder: 'Password enkripsi (kosongkan jika tidak ada)...',
      confirmDecryptBtn: 'Dekripsi & Buka',
      confirmDelete: 'Yakin ingin menghapus file "{name}" secara permanen dari Vault?'
    },
    keys: {
      title: 'Kunci Vault Milik Anda (Author)',
      subtitle: 'Daftar kunci kriptografi dari file yang Anda enkripsi sendiri. Anda dapat menyalin kunci, memperbarui password, atau menghapus file.',
      loading: 'Memuat daftar kunci vault...',
      empty: 'Belum ada kunci file yang dienkripsi oleh Anda.',
      colFileName: 'Nama File & Kunci',
      colAlgorithm: 'Algoritma',
      colPassword: 'Password Enkripsi',
      colCreated: 'Dibuat Pada',
      colActions: 'Aksi',
      btnCopyKey: 'Salin Key',
      btnCopied: 'Disalin!',
      btnUpdatePass: 'Ubah Password',
      btnDelete: 'Hapus',
      btnDownload: 'Download File',
      noPassword: '(tanpa password)',
      modalUpdateTitle: 'Perbarui Password Enkripsi',
      modalUpdateDesc: 'Ubah password yang digunakan untuk melindungi file "{name}". Kosongkan jika ingin menghapus proteksi password.',
      newPassPlaceholder: 'Password baru (kosongkan untuk hapus password)...',
      btnSavePass: 'Simpan Password',
      confirmDelete: 'Apakah Anda yakin ingin menghapus file "{name}" beserta seluruh kuncinya secara permanen?'
    },
    workspace: {
      title: 'Workspace',
      tabOrg: 'Organisasi',
      tabConnections: 'Koneksi Saya',
      searchFriends: 'Cari & Tambah Teman',
      searchPlaceholder: 'Ketik username untuk mencari teman...',
      searchResults: 'Hasil Pencarian',
      noUsersFound: 'Tidak ada pengguna ditemukan dengan username "{query}".',
      btnSendRequest: 'Kirim Permintaan',
      btnSending: 'Mengirim...',
      pendingSent: '⏳ Menunggu Persetujuan',
      pendingReceived: 'Terima Permintaan',
      connected: '✓ Terhubung',
      pendingApprovalHeader: 'Menunggu Persetujuan Anda',
      btnAccept: 'Terima',
      btnReject: 'Tolak',
      activeConnections: 'Daftar Koneksi Aktif',
      noActiveConnections: 'Anda belum memiliki koneksi aktif.',
      btnSendFile: 'Kirim File',
      btnRemoveConnection: 'Putuskan Koneksi',
      confirmRemoveConnection: 'Apakah Anda yakin ingin memutuskan koneksi dengan {name}?',
      personalWorkspaceNotice: 'Anda saat ini berada di Personal Workspace. Gunakan menu dropdown di kiri atas untuk berpindah konteks organisasi.',
      btnJoinOrg: 'Gabung Organisasi',
      btnCreateOrg: 'Buat Organisasi',
      orgMembers: 'Anggota: {name}',
      noOrgMembers: 'Belum ada anggota.',
      btnInviteMember: '+ Undang Member',
      btnLeaveOrg: 'Keluar',
      confirmLeaveOrg: 'Yakin ingin keluar dari organisasi "{name}"?'
    },
    settings: {
      title: 'Pengaturan',
      appearance: 'Tampilan & Bahasa',
      language: 'Bahasa Aplikasi',
      langId: 'Bahasa Indonesia (ID)',
      langEn: 'English (EN)',
      theme: 'Tema',
      themeLight: 'Terang',
      themeDark: 'Gelap',
      themeSystem: 'Sistem',
      notifications: 'Notifikasi Desktop',
      startup: 'Jalankan Saat Startup',
      account: 'Akun',
      signOut: 'Keluar dari Akun'
    },
    about: {
      title: 'Tentang Faycryptor',
      description: 'Faycryptor adalah solusi enkripsi multi-layer canggih yang dirancang untuk melindungi kerahasiaan data tingkat tinggi menggunakan kombinasi algoritma standar industri dan cipher kustom inovatif.'
    }
  },
  en: {
    common: {
      appName: 'Faycryptor',
      loading: 'Loading...',
      save: 'Save',
      cancel: 'Cancel',
      delete: 'Delete',
      close: 'Close',
      search: 'Search',
      prev: 'Previous',
      next: 'Next',
      pageOf: 'Page {current} of {total}',
      actions: 'Actions',
      status: 'Status',
      date: 'Date',
      author: 'Author',
      algorithm: 'Algorithm',
      fileName: 'File Name',
      success: 'Success',
      error: 'An Error Occurred',
      confirm: 'Confirm'
    },
    nav: {
      overview: 'Overview',
      home: 'Home',
      fileOps: 'File Operations',
      encrypt: 'Encrypt',
      file: 'File Decryption',
      keys: 'View Keys',
      collaboration: 'Collaboration',
      workspace: 'Workspace',
      general: 'General',
      settings: 'Settings',
      about: 'About',
      personal: 'Personal',
      createOrg: '+ Create Organization...',
      vaultConnected: 'Vault connected'
    },
    home: {
      welcome: 'Welcome to Faycryptor',
      subtitle: 'Self-custodial military-grade file encryption system with Web Vault synchronization.',
      quickActions: 'Quick Actions',
      encryptCardTitle: 'Encrypt Files',
      encryptCardDesc: 'Secure local files with AES-256 or FayCipher.',
      decryptCardDesc: 'Unlock & inspect encrypted files from vault or local folders.',
      decryptCardTitle: 'Decrypt Files',
      workspaceCardTitle: 'Workspace',
      workspaceCardDesc: 'Manage organizations & file sharing connections.',
      recentActivity: 'Recent Activity',
      noActivity: 'No recent encryption or decryption history.',
      statsTotal: 'Protected Files',
      statsDecrypted: 'Decrypted Files',
      statsConnections: 'Active Connections'
    },
    encrypt: {
      title: 'Encrypt Files & Folders',
      selectFolder: 'Select Folder or File',
      browseBtn: 'Choose File...',
      algorithm: 'Encryption Algorithm',
      passwordOptional: 'Encryption Password (Optional)',
      passwordPlaceholder: 'Enter protection password...',
      vaultStore: 'Save encrypted copy to Web Vault',
      encryptBtn: 'Start Encryption',
      encrypting: 'Encrypting...',
      successMsg: 'File encrypted and secured successfully!',
      errorMsg: 'Failed to encrypt file.'
    },
    decrypt: {
      title: 'File List & Decryption',
      filterLabel: 'Filter:',
      filterAll: 'All Files',
      filterEncrypted: 'Encrypted',
      filterDecrypted: 'Decrypted',
      filterMine: 'My Files',
      filterOrg: 'From Organization',
      filterConnections: 'From Connections',
      searchPlaceholder: 'Search name, path, author...',
      statusEncrypted: '🔒 Encrypted',
      statusDecrypted: '✓ Decrypted',
      btnDecrypt: 'Decrypt',
      btnOpen: 'Open',
      btnDelete: 'Delete',
      emptyVault: 'No files in vault yet. Encrypt a file first.',
      noMatch: 'No files matched the filter.',
      modalTitle: 'Decrypt Vault File',
      modalDesc: 'Enter encryption password to unlock this file:',
      passPlaceholder: 'Encryption password (leave blank if none)...',
      confirmDecryptBtn: 'Decrypt & Open',
      confirmDelete: 'Are you sure you want to permanently delete "{name}" from Vault?'
    },
    keys: {
      title: 'My Vault Keys (Author Only)',
      subtitle: 'List of cryptographic keys from files encrypted by you. You can copy keys, update passwords, or delete files.',
      loading: 'Loading vault keys...',
      empty: 'No encrypted file keys owned by you yet.',
      colFileName: 'File & Key Name',
      colAlgorithm: 'Algorithm',
      colPassword: 'Encryption Password',
      colCreated: 'Created At',
      colActions: 'Actions',
      btnCopyKey: 'Copy Key',
      btnCopied: 'Copied!',
      btnUpdatePass: 'Update Password',
      btnDelete: 'Delete',
      btnDownload: 'Download File',
      noPassword: '(no password)',
      modalUpdateTitle: 'Update Encryption Password',
      modalUpdateDesc: 'Change the password used to protect file "{name}". Leave blank to remove password protection.',
      newPassPlaceholder: 'New password (leave blank to remove password)...',
      btnSavePass: 'Save Password',
      confirmDelete: 'Are you sure you want to permanently delete file "{name}" and all its keys?'
    },
    workspace: {
      title: 'Workspace',
      tabOrg: 'Organization',
      tabConnections: 'My Connections',
      searchFriends: 'Search & Add Friends',
      searchPlaceholder: 'Type username to search for friends...',
      searchResults: 'Search Results',
      noUsersFound: 'No users found with username "{query}".',
      btnSendRequest: 'Send Request',
      btnSending: 'Sending...',
      pendingSent: '⏳ Pending Approval',
      pendingReceived: 'Accept Request',
      connected: '✓ Connected',
      pendingApprovalHeader: 'Awaiting Your Approval',
      btnAccept: 'Accept',
      btnReject: 'Reject',
      activeConnections: 'Active Connections',
      noActiveConnections: 'You have no active connections yet.',
      btnSendFile: 'Send File',
      btnRemoveConnection: 'Remove Connection',
      confirmRemoveConnection: 'Are you sure you want to disconnect with {name}?',
      personalWorkspaceNotice: 'You are currently in Personal Workspace. Use the dropdown at top-left to switch organization context.',
      btnJoinOrg: 'Join Organization',
      btnCreateOrg: 'Create Organization',
      orgMembers: 'Members: {name}',
      noOrgMembers: 'No members yet.',
      btnInviteMember: '+ Invite Member',
      btnLeaveOrg: 'Leave',
      confirmLeaveOrg: 'Are you sure you want to leave organization "{name}"?'
    },
    settings: {
      title: 'Settings',
      appearance: 'Appearance & Language',
      language: 'App Language',
      langId: 'Bahasa Indonesia (ID)',
      langEn: 'English (EN)',
      theme: 'Theme',
      themeLight: 'Light',
      themeDark: 'Dark',
      themeSystem: 'System',
      notifications: 'Desktop Notifications',
      startup: 'Launch on Startup',
      account: 'Account',
      signOut: 'Sign Out'
    },
    about: {
      title: 'About Faycryptor',
      description: 'Faycryptor is an advanced multi-layer encryption suite designed for high-security data confidentiality combining industry-standard algorithms with custom cipher innovations.'
    }
  }
}

const LanguageContext = createContext({
  language: 'id',
  setLanguage: () => {},
  t: () => ''
})

export function LanguageProvider({ children }) {
  const [language, setLanguageState] = useState(() => {
    return localStorage.getItem('app_language') || 'id'
  })

  const setLanguage = (lang) => {
    setLanguageState(lang)
    localStorage.setItem('app_language', lang)
  }

  const t = (path, params = {}) => {
    const keys = path.split('.')
    let current = translations[language] || translations.id

    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key]
      } else {
        // Fallback to Indonesian if key is missing in English
        let fallback = translations.id
        for (const fbKey of keys) {
          if (fallback && typeof fallback === 'object' && fbKey in fallback) {
            fallback = fallback[fbKey]
          } else {
            return path
          }
        }
        current = fallback
        break
      }
    }

    if (typeof current !== 'string') {
      return path
    }

    let result = current
    for (const [paramKey, paramVal] of Object.entries(params)) {
      result = result.replace(new RegExp(`\\{${paramKey}\\}`, 'g'), String(paramVal))
    }
    return result
  }

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  )
}

export function useTranslation() {
  return useContext(LanguageContext)
}
