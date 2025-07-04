import { useState, useEffect } from 'react';
import { redisHelpers } from '../lib/redis.js';

// Custom hook for managing user sessions with Redis
export function useUserSession(userId) {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!userId) {
      setLoading(false);
      return;
    }

    const fetchSession = async () => {
      try {
        const sessionData = await redisHelpers.getUserSession(userId);
        setSession(sessionData);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchSession();
  }, [userId]);

  const updateSession = async (newSessionData) => {
    try {
      await redisHelpers.setUserSession(userId, newSessionData);
      setSession(newSessionData);
    } catch (err) {
      setError(err.message);
    }
  };

  return { session, loading, error, updateSession };
}

// Custom hook for managing user preferences with Redis
export function useUserPreferences(userId) {
  const [preferences, setPreferences] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!userId) {
      setLoading(false);
      return;
    }

    const fetchPreferences = async () => {
      try {
        const prefs = await redisHelpers.getUserPreferences(userId);
        setPreferences(prefs);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchPreferences();
  }, [userId]);

  const updatePreferences = async (newPreferences) => {
    try {
      await redisHelpers.setUserPreferences(userId, newPreferences);
      setPreferences(newPreferences);
    } catch (err) {
      setError(err.message);
    }
  };

  return { preferences, loading, error, updatePreferences };
}

// Custom hook for caching documents with Redis
export function useDocumentCache(documentId) {
  const [document, setDocument] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!documentId) {
      setLoading(false);
      return;
    }

    const fetchDocument = async () => {
      try {
        const docData = await redisHelpers.getCachedDocument(documentId);
        setDocument(docData);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchDocument();
  }, [documentId]);

  const cacheDocument = async (documentData, expirationSeconds = 7200) => {
    try {
      await redisHelpers.cacheDocument(documentId, documentData, expirationSeconds);
      setDocument(documentData);
    } catch (err) {
      setError(err.message);
    }
  };

  return { document, loading, error, cacheDocument };
}