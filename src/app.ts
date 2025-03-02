import express, { Request, Response } from 'express';
import { makeWASocket, useMultiFileAuthState, DisconnectReason } from '@whiskeysockets/baileys';
import QRCode from 'qrcode';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { createHash } from 'crypto';
import fs from 'fs';
import { promises as fsPromises } from 'fs';
import { appendFileSync } from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Define interfaces
interface Session {
  authDir: string;
  sessionId: string;
  name: string;
  phoneNumber: string;
  qrCode: string | null;
  sock: ReturnType<typeof makeWASocket>;
  registered: boolean;
  groupName: string;
  forwardGroupId: string | null;
}

interface CreateSessionBody {
  name: string;
  phoneNumber: string;
  groupName: string;
}

// Create Express app
const app = express();
app.use(cors());
app.use(express.json());

// Create Express Router
const router = express.Router();

// Add logging middleware
app.use((req: Request, res: Response, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Storage for sessions
const sessions = new Map<string, Session>();

// Track which socket belongs to which session
const socketSessionMap = new Map<string, string>();

// Helper function to determine current directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Logging utility function
function logToFile(data: any, prefix: string = 'debug') {
  try {
    const logDir = path.resolve(process.cwd(), 'logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    
    const timestamp = new Date().toISOString();
    const logFile = path.join(logDir, `whatsapp-${new Date().toISOString().split('T')[0]}.log`);
    
    let logData = `\n[${timestamp}] [${prefix}] `;
    if (typeof data === 'object') {
      logData += JSON.stringify(data, null, 2);
    } else {
      logData += data;
    }
    
    appendFileSync(logFile, logData);
    console.log(`Logged to ${logFile}`);
  } catch (error) {
    console.error('Failed to write log:', error);
  }
}

// Global message handler setup
function setupGlobalMessageHandlers() {
  console.log("Setting up global message handlers");
  logToFile("Setting up global message handlers", "SETUP");
}

// Function to create new socket with message handlers attached
// Function to create new socket with message handlers attached
function createSocketWithHandlers(authDir: string, sessionId: string) {
    return new Promise<ReturnType<typeof makeWASocket>>((resolve, reject) => {
      useMultiFileAuthState(authDir)
        .then(({ state, saveCreds }) => {
          const sock = makeWASocket({
            printQRInTerminal: true,
            browser: ['WhatsApp', 'Web', '2.2311.3'],
            auth: state,
            version: [2, 3000, 200924]
          });
          
          // Register this socket to its session
          const sockId = sock.user?.id || Date.now().toString();
          socketSessionMap.set(sockId, sessionId);
          console.log(`Registered socket ${sockId} to session ${sessionId}`);
          
          // Set up message handling for this socket specifically
          sock.ev.on('messages.upsert', async ({ messages, type }: any) => {
            console.log(`[RECEIVED MESSAGE] Socket: ${sockId}, Session: ${sessionId}, Type: ${type}, Count: ${messages?.length}`);
            logToFile({ 
              event: 'messages.upsert', 
              sockId, 
              sessionId, 
              type, 
              count: messages?.length 
            }, 'MESSAGE_RECEIVED');
            
            const session = sessions.get(sessionId);
            if (!session || !session.sock || !messages) {
              console.error('Cannot process messages: invalid session state');
              return;
            }
            
            // Debug: Log ALL incoming messages
            console.log("ALL INCOMING MESSAGES:", JSON.stringify(messages, null, 2));
            logToFile(messages, 'ALL_INCOMING');
            
            for (const message of messages) {
              try {
                // Log raw message for debugging
                console.log('PROCESSING RAW MESSAGE:', JSON.stringify(message, null, 2));
                logToFile(message, 'RAW_MESSAGE_DETAIL');
                
                if (message.key?.fromMe || message.messageStubType) {
                  console.log('Skipping message (from me or system message)');
                  continue;
                }
                
                // Extract text from all possible message formats with detailed logging
                let messageText = '';
                let textSource = 'unknown';
                
                if (message.message?.conversation && message.message.conversation.trim() !== '') {
                  messageText = message.message.conversation;
                  textSource = 'conversation';
                  console.log(`Text from conversation field: "${messageText}"`);
                } 
                else if (message.message?.extendedTextMessage?.text && message.message.extendedTextMessage.text.trim() !== '') {
                  messageText = message.message.extendedTextMessage.text;
                  textSource = 'extendedTextMessage';
                  console.log(`Text from extendedTextMessage field: "${messageText}"`);
                }
                else if (message.message?.buttonsResponseMessage?.selectedDisplayText && 
                         message.message.buttonsResponseMessage.selectedDisplayText.trim() !== '') {
                  messageText = message.message.buttonsResponseMessage.selectedDisplayText;
                  textSource = 'buttonsResponse';
                  console.log(`Text from buttonsResponse field: "${messageText}"`);
                }
                else {
                  // Try to find text in any property
                  console.log("Checking other message types...");
                  const messageObj = message.message || {};
                  for (const key in messageObj) {
                    if (typeof messageObj[key]?.text === 'string' && messageObj[key].text.trim() !== '') {
                      messageText = messageObj[key].text;
                      textSource = `${key}.text`;
                      console.log(`Text from ${textSource} field: "${messageText}"`);
                      break;
                    }
                  }
                }
                
                if (!messageText || messageText.trim() === '') {
                  console.log('No text content found in message');
                  continue;
                }
                
                // Log extracted message details
                logToFile({ 
                  text: messageText, 
                  source: textSource,
                  fromJid: message.key.remoteJid
                }, 'EXTRACTED_TEXT');
                
                // Check for forwarding trigger - more lenient matching
                const normalizedText = messageText.trim();
                if (normalizedText.startsWith('Re-envía:') || 
                    normalizedText.startsWith('Re-envia:') ||
                    normalizedText.startsWith('Re-envíá:') ||
                    normalizedText.startsWith('Reenvia:') ||
                    normalizedText.startsWith('Reenvía:')) {
                  
                  console.log('✅ FOUND forwarding trigger message!');
                  logToFile({ trigger: normalizedText.split(':', 1)[0], text: messageText }, 'TRIGGER_FOUND');

                  const prefixMatch = normalizedText.match(/^(Re-envía:|Re-envia:|Re-envíá:|Reenvia:|Reenvía:)\s*/);
                  const prefixLength = prefixMatch ? prefixMatch[0].length : 0;
                  const forwardText = messageText.substring(prefixLength).trim();
                  
                  if (session.forwardGroupId) {
                    try {
                      console.log(`Attempting to forward message to group: ${session.forwardGroupId}`);
                      await session.sock.sendMessage(session.forwardGroupId, { 
                        text: forwardText 
                      });
                      console.log('Message forwarded successfully');
                      logToFile({ success: true, groupId: session.forwardGroupId }, 'FORWARD_SUCCESS');
                    } catch (error) {
                      console.error('Failed to forward message:', error);
                      logToFile({ error: String(error) }, 'FORWARD_ERROR');
                    }
                  } else {
                    console.error(`No forward group configured for: ${session.groupName}`);
                    logToFile({ error: 'No target group', groupName: session.groupName }, 'NO_TARGET');
                  }
                } else {
                  console.log('Message does not match forwarding criteria');
                  logToFile({ 
                    text: messageText.substring(0, 50) + (messageText.length > 50 ? '...' : ''),
                    matches: false 
                  }, 'NO_MATCH');
                }
              } catch (error) {
                console.error('Error processing message:', error);
                logToFile({ error: String(error) }, 'PROCESS_ERROR');
              }
            }
          });
          
          // Set up other event listeners for debugging
          sock.ev.on('messaging-history.set', () => {
            console.log(`Messaging history set for session ${sessionId}`);
            logToFile(`Messaging history set for session ${sessionId}`, 'HISTORY_SET');
          });
          
          sock.ev.on('presence.update', (data) => {
            console.log(`Presence update for session ${sessionId}:`, data);
            logToFile({ sessionId, ...data }, 'PRESENCE_UPDATE');
          });
          
          // Set up creds update handler
          sock.ev.on('creds.update', saveCreds);
          
          resolve(sock);
        })
        .catch(error => {
          reject(error);
        });
    });
  }

// Auto check all sessions function
const autoCheckSessions = async () => {
  console.log('Auto-checking all sessions...');
  
  for (const [sessionId, session] of sessions.entries()) {
    if (session.sock && !session.registered) {
      try {
        console.log(`Auto-registering session ${sessionId}`);
        
        // Try to fetch groups to verify connection is working
        const groups = await session.sock.groupFetchAllParticipating();
        if (groups) {
          console.log(`Session ${sessionId} connection verified - marking as registered`);
          session.registered = true;
          
          // Process groups to find target
          const groupsList = Object.values(groups).map((g: any) => ({
            id: g.id,
            name: g.subject || 'No Name',
            participants: g.participants?.length || 0
          }));
          
          console.table(groupsList);
          logToFile(groupsList, 'AUTO_GROUPS');
          
          // Find group with exact or partial match
          const foundGroup = groupsList.find(g => 
            g.name.toLowerCase() === session.groupName.toLowerCase() ||
            g.name.toLowerCase().includes(session.groupName.toLowerCase()) ||
            session.groupName.toLowerCase().includes(g.name.toLowerCase())
          );
          
          if (foundGroup) {
            session.forwardGroupId = foundGroup.id;
            console.log(`Auto-found group: ${foundGroup.name}`);
            logToFile({ foundGroup: foundGroup.name, id: foundGroup.id }, 'GROUP_FOUND');
          }
        }
      } catch (error) {
        console.log(`Auto-check failed for session ${sessionId}:`, error);
        logToFile({ error: String(error), sessionId }, 'AUTO_CHECK_ERROR');
      }
    }
  }
};

// Helper function to log available groups
const logAvailableGroups = async (session: Session) => {
  try {
    console.log('Attempting to fetch groups for session:', session.sessionId);
    const groups = await session.sock.groupFetchAllParticipating();
    console.log('===== AVAILABLE GROUPS =====');
    
    const groupsList = Object.values(groups).map((g: any) => ({
      id: g.id,
      name: g.subject || 'No Name',
      participants: g.participants?.length || 0
    }));
    
    console.table(groupsList);
    logToFile(groupsList, 'GROUPS');
    console.log('Looking for group name:', session.groupName);
    
    // First try exact match
    let foundGroup = groupsList.find(g => g.name === session.groupName);
    
    // If not found, try case-insensitive match
    if (!foundGroup) {
      console.log('Exact match not found, trying case-insensitive match');
      foundGroup = groupsList.find(g => 
        g.name.toLowerCase() === session.groupName.toLowerCase()
      );
    }
    
    // If still not found, try removing URL encoding
    if (!foundGroup) {
      const decodedName = decodeURIComponent(session.groupName);
      console.log('Case-insensitive match not found, trying decoded name:', decodedName);
      foundGroup = groupsList.find(g => 
        g.name.toLowerCase() === decodedName.toLowerCase()
      );
      
      // If found with decoded name, update the session
      if (foundGroup) {
        console.log('Found group with decoded name');
        session.groupName = decodedName;
      }
    }
    
    // If still not found, try partial match
    if (!foundGroup) {
      console.log('Trying partial match');
      const partialMatches = groupsList.filter(g => 
        g.name.toLowerCase().includes(session.groupName.toLowerCase()) ||
        session.groupName.toLowerCase().includes(g.name.toLowerCase())
      );
      
      if (partialMatches.length === 1) {
        foundGroup = partialMatches[0];
        console.log(`Found single partial match: ${foundGroup.name}`);
      }
    }
    
    if (foundGroup) {
      console.log(`✅ Found target group: ${foundGroup.name} (${foundGroup.id})`);
      logToFile({ foundGroup: foundGroup.name, id: foundGroup.id }, 'GROUP_FOUND');
      session.forwardGroupId = foundGroup.id;
    } else {
      console.log(`❌ Target group not found: ${session.groupName}`);
      logToFile({ error: 'Group not found', name: session.groupName }, 'GROUP_NOT_FOUND');
      console.log('Available groups:', groupsList.map(g => g.name).join(', '));
    }
    
    return groupsList;
  } catch (error) {
    console.error('Failed to fetch groups:', error);
    logToFile({ error: String(error) }, 'FETCH_GROUPS_ERROR');
    return [];
  }
};

// Helper function to save registered users to a JSON file
const saveVendor = async (session: Session) => {
  const vendorsPath = resolve(process.cwd(), 'src/registeredVendors/vendors.json');

  let existingVendors: any[] = [];
  try {
    const jsonData = await fsPromises.readFile(vendorsPath, 'utf-8');
    existingVendors = JSON.parse(jsonData);
  } catch {
    existingVendors = [];
  }

  const isDuplicate = existingVendors.some(v => v.phoneNumber === session.phoneNumber);
  if (!isDuplicate) {
    existingVendors.push({
      name: session.name,
      phoneNumber: session.phoneNumber
    });
    await fsPromises.writeFile(vendorsPath, JSON.stringify(existingVendors, null, 2));
  }
};

// Handler for creating a session - updated to use the new socket creation method
router.post('/create-session', async (req: Request, res: Response) => {
  try {
    const { name, phoneNumber, groupName } = req.body as CreateSessionBody;

    if (!name || !phoneNumber || !groupName) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }

    const cleanedPhone = phoneNumber.replace(/\D/g, '');
    const hashedPhone = createHash('md5').update(cleanedPhone).digest('hex');
    const authDir = resolve(process.cwd(), 'src/auth', `auth_${hashedPhone}`);
    const sessionId = uuidv4();

    // Remove existing session with the same phone number
    for (const [sessionKey, session] of Array.from(sessions.entries())) {
      if (session.phoneNumber === cleanedPhone) {
        sessions.delete(sessionKey);
        session.sock?.logout();
      }
    }

    // Create authorization directory
    if (!fs.existsSync(authDir)) {
      fs.mkdirSync(authDir, { recursive: true });
    }

    try {
      // Initialize socket with handlers
      const sock = await createSocketWithHandlers(authDir, sessionId);

      // Register the session
      const newSession: Session = {
        authDir,
        sessionId,
        name,
        phoneNumber: cleanedPhone,
        qrCode: null,
        sock,
        registered: false,
        groupName,
        forwardGroupId: null
      };
      
      sessions.set(sessionId, newSession);

      // Handle connection updates
      sock.ev.on('connection.update', async ({ connection, qr, lastDisconnect }: any) => {
        const session = sessions.get(sessionId);
        if (!session || !session.sock) return;

        console.log(`Connection update for session ${sessionId}:`, { connection, hasQr: !!qr });
        logToFile({ connection, hasQr: !!qr, sessionId }, 'CONNECTION_UPDATE');

        if (qr) {
          console.log('New QR code generated, updating session QR');
          QRCode.toDataURL(qr, (_, url) => session.qrCode = url);
        }

        if (connection === 'open') {
          console.log(`Connection OPEN for session ${sessionId}`);
          logToFile({ status: 'open', sessionId }, 'CONNECTION_OPEN');
          session.registered = true;
          saveVendor(session);

          // Wait a moment for the connection to stabilize before fetching groups
          setTimeout(async () => {
            try {
              console.log('Fetching groups after connection established');
              await logAvailableGroups(session);
            } catch (error) {
              console.error(`Error fetching groups:`, error);
              logToFile({ error: String(error) }, 'FETCH_GROUPS_ERROR');
            }
          }, 3000);
        }

        if (connection === 'close' && lastDisconnect?.error) {
          const statusCode = (lastDisconnect.error as any).output?.statusCode;
          const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
          console.log(`Connection CLOSED for session ${sessionId}`, { 
            errorCode: statusCode,
            shouldReconnect
          });
          logToFile({ 
            status: 'closed', 
            errorCode: statusCode, 
            shouldReconnect,
            sessionId 
          }, 'CONNECTION_CLOSE');
          
          if (shouldReconnect) {
            console.log('Reconnecting...');
            try {
              // Recreate socket with handlers when reconnecting
              const newSock = await createSocketWithHandlers(authDir, sessionId);
              session.sock = newSock;
              session.registered = false;
              session.qrCode = null;
              console.log('Reconnected successfully');
              logToFile({ status: 'reconnected', sessionId }, 'CONNECTION_RECONNECT');
            } catch (error) {
              console.error('Reconnect error:', error);
              logToFile({ error: String(error) }, 'RECONNECT_ERROR');
            }
          }
        }
      });

      res.json({ sessionId, qrCodeUrl: `/qr-image/${sessionId}`, groupName });
    } catch (error) {
      res.status(500).json({ error: 'Failed to create session' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// Handler for serving QR code image
router.get('/qr-image/:sessionId', (req: Request<{ sessionId: string }>, res: Response) => {
  const session = sessions.get(req.params.sessionId);
  if (!session || !session.qrCode) {
    res.status(404).json({ error: 'QR code not found' });
  } else {
    const base64Data = session.qrCode.split(',')[1];
    res.writeHead(200, { 'Content-Type': 'image/png' });
    res.end(Buffer.from(base64Data, 'base64'));
  }
});

// New endpoint: Check session status with auto-registration
router.get('/session-status/:sessionId', async (req: Request<{sessionId: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  // Auto-register if socket exists but not marked as registered
  if (session.sock && !session.registered) {
    try {
      console.log(`Auto-registering session ${sessionId}`);
      logToFile({ action: 'auto-register', sessionId }, 'AUTO_REGISTER');
      session.registered = true;
      
      // Try to fetch groups to verify connection is working
      const groups = await session.sock.groupFetchAllParticipating();
      if (groups) {
        console.log('Connection verified - groups fetched successfully');
        
        // Process groups to find target
        const groupsList = Object.values(groups).map((g: any) => ({
          id: g.id,
          name: g.subject || 'No Name',
          participants: g.participants?.length || 0
        }));
        
        // Find group with exact or partial match
        const foundGroup = groupsList.find(g => 
          g.name.toLowerCase() === session.groupName.toLowerCase() ||
          g.name.toLowerCase().includes(session.groupName.toLowerCase()) ||
          session.groupName.toLowerCase().includes(g.name.toLowerCase())
        );
        
        if (foundGroup) {
          session.forwardGroupId = foundGroup.id;
          console.log(`Auto-found group: ${foundGroup.name}`);
          logToFile({ group: foundGroup.name, id: foundGroup.id }, 'GROUP_FOUND');
        }
      }
    } catch (error) {
      console.log('Auto-registration failed:', error);
      logToFile({ error: String(error) }, 'AUTO_REGISTER_ERROR');
      // Don't change registration status if error
      session.registered = false;
    }
  }
  
  res.json({
    name: session.name,
    phoneNumber: session.phoneNumber,
    registered: session.registered,
    groupName: session.groupName,
    forwardGroupId: session.forwardGroupId,
    hasForwardGroup: !!session.forwardGroupId
  });
});

// Enhanced refresh groups endpoint
router.post('/refresh-groups/:sessionId', async (req: Request<{sessionId: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  // Check if the session is properly connected to WhatsApp
  console.log(`Checking session state for ${sessionId}:`, {
    registered: session.registered,
    hasConnection: !!session.sock
  });
  
  // Auto-register if session has a socket but is not registered
  if (session.sock && !session.registered) {
    console.log(`Auto-registering session ${sessionId} during refresh`);
    logToFile({ action: 'auto-register', sessionId, context: 'refresh-groups' }, 'AUTO_REGISTER');
    session.registered = true;
  }
  
  if (!session.registered) {
    res.status(400).json({ 
      error: 'Session not registered yet',
      sessionState: {
        hasSocket: !!session.sock,
        registered: session.registered,
        phoneNumber: session.phoneNumber,
        groupName: session.groupName
      },
      hint: 'Scan the QR code to authenticate. If already scanned, wait a moment and try again.'
    });
    return;
  }
  
  try {
    console.log('Attempting to fetch groups for:', session.groupName);
    
    // Force fetch all groups
    const rawGroups = await session.sock.groupFetchAllParticipating();
    console.log('===== FETCHED GROUPS =====');
    
    const groupsList = Object.values(rawGroups).map((g: any) => ({
      id: g.id,
      name: g.subject || 'No Name',
      participants: g.participants?.length || 0
    }));
    
    console.table(groupsList);
    logToFile(groupsList, 'REFRESH_GROUPS');
    
    // Try several matching strategies
    console.log('Searching for group:', session.groupName);
    
    // 1. Exact match
    let foundGroup = groupsList.find(g => g.name === session.groupName);
    
    // 2. Case-insensitive match
    if (!foundGroup) {
      console.log('Trying case-insensitive match');
      foundGroup = groupsList.find(g => 
        g.name.toLowerCase() === session.groupName.toLowerCase()
      );
    }
    
    // 3. Decode URL-encoded characters
    if (!foundGroup) {
      const decodedName = decodeURIComponent(session.groupName);
      console.log('Trying decoded name:', decodedName);
      foundGroup = groupsList.find(g => 
        g.name.toLowerCase() === decodedName.toLowerCase()
      );
      
      if (foundGroup) {
        session.groupName = decodedName;
      }
    }
    
    // 4. Try partial match as last resort
    let partialMatches = [];
    if (!foundGroup) {
      console.log('Trying partial match');
      partialMatches = groupsList.filter(g => 
        g.name.toLowerCase().includes(session.groupName.toLowerCase()) ||
        session.groupName.toLowerCase().includes(g.name.toLowerCase())
      );
      
      if (partialMatches.length === 1) {
        foundGroup = partialMatches[0];
        console.log(`Found single partial match: ${foundGroup.name}`);
      }
    }
    
    if (foundGroup) {
      console.log(`Group found: ${foundGroup.name} (${foundGroup.id})`);
      logToFile({ group: foundGroup.name, id: foundGroup.id }, 'GROUP_FOUND');
      session.forwardGroupId = foundGroup.id;
      
      res.json({ 
        success: true, 
        groups: groupsList,
        targetGroup: session.groupName,
        foundGroup: foundGroup.name,
        forwardGroupId: session.forwardGroupId,
        forwardGroupFound: true
      });
    } else {
      console.log('Group not found in any matching attempt');
      logToFile({ error: 'Group not found', name: session.groupName }, 'GROUP_NOT_FOUND');
      
      res.json({ 
        success: false, 
        groups: groupsList,
        targetGroup: session.groupName,
        forwardGroupId: null,
        forwardGroupFound: false,
        partialMatches: partialMatches.length > 0 ? partialMatches.map(g => g.name) : [],
        suggestion: partialMatches.length > 0 
          ? `Try using one of these similar group names: ${partialMatches.map(g => g.name).join(', ')}`
          : `Available groups: ${groupsList.map(g => g.name).join(', ')}`
      });
    }
  } catch (error: any) {
    console.error('Failed to refresh groups:', error);
    logToFile({ error: error.message, stack: error.stack }, 'REFRESH_GROUPS_ERROR');
    res.status(500).json({ 
      error: 'Failed to refresh groups', 
      details: error.message,
      stack: error.stack
    });
  }
});

// New endpoint: Test forwarding
router.post('/test-forward/:sessionId', async (req: Request<{sessionId: string}, any, {message?: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const { message } = req.body;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  // Auto-register if session has a socket but is not registered
  if (session.sock && !session.registered) {
    console.log(`Auto-registering session ${sessionId} during test forward`);
    logToFile({ action: 'auto-register', sessionId, context: 'test-forward' }, 'AUTO_REGISTER');
    session.registered = true;
  }
  
  if (!session.forwardGroupId) {
    res.status(400).json({ 
      error: 'No forward group found',
      groupName: session.groupName
    });
    return;
  }
  
  if (!session.registered) {
    res.status(400).json({ error: 'Session not registered yet' });
    return;
  }
  
  try {
    const testMessageWithPrefix = message || `Re-envía: Test message sent at ${new Date().toISOString()}`;
   
    const prefixMatch = testMessageWithPrefix.match(/^(Re-envía:|Re-envia:|Re-envíá:|Reenvia:|Reenvía:)\s*/);
    const prefixLength = prefixMatch ? prefixMatch[0].length : 0;
    const forwardText = testMessageWithPrefix.substring(prefixLength).trim();

    await session.sock.sendMessage(session.forwardGroupId, { text: forwardText });
    logToFile({ originalMessage: testMessageWithPrefix, forwardedMessage: forwardText, groupId: session.forwardGroupId }, 'TEST_FORWARD');
    
    res.json({ 
      success: true, 
      message: 'Test message forwarded successfully',
      forwardedTo: session.forwardGroupId,
      originalMessage: testMessageWithPrefix,
      forwardedMessage: forwardText
    });
  } catch (error: any) {
    console.error('Test forward failed:', error);
    logToFile({ error: error.message }, 'TEST_FORWARD_ERROR');
    res.status(500).json({ 
      error: 'Failed to forward test message', 
      details: error.message 
    });
  }
});

// Force register session endpoint for fixing registration issues
router.post('/force-register/:sessionId', async (req: Request<{sessionId: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  // Force set registered status
  session.registered = true;
  logToFile({ action: 'force-register', sessionId }, 'FORCE_REGISTER');
  
  try {
    // Get and log all available groups
    const groups = await session.sock.groupFetchAllParticipating();
    console.log('===== AVAILABLE GROUPS =====');
    
    const groupsList = Object.values(groups).map((g: any) => ({
      id: g.id,
      name: g.subject || 'No Name',
      participants: g.participants?.length || 0
    }));
    
    console.table(groupsList);
    logToFile(groupsList, 'FORCE_REGISTER_GROUPS');
    
    // Try to find the target group
    const foundGroup = groupsList.find(g => 
      g.name.toLowerCase() === session.groupName.toLowerCase() ||
      g.name.toLowerCase().includes('testing-group') ||
      g.name.toLowerCase().includes('test')
    );
    
    if (foundGroup) {
      session.forwardGroupId = foundGroup.id;
      session.groupName = foundGroup.name;
      console.log(`Found group: ${foundGroup.name}`);
      logToFile({ group: foundGroup.name, id: foundGroup.id }, 'GROUP_FOUND');
    }
    
    res.json({
      success: true,
      registered: session.registered,
      groups: groupsList,
      foundGroup: foundGroup || null,
      forwardGroupId: session.forwardGroupId
    });
  } catch (error: any) {
    console.error('Error in force-register:', error);
    logToFile({ error: error.message }, 'FORCE_REGISTER_ERROR');
    res.status(500).json({
      error: 'Failed to register session',
      message: error.message
    });
  }
});

// Manual group setting endpoint
router.post('/set-group/:sessionId', async (req: Request<{sessionId: string}, any, {groupId?: string, groupName?: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const { groupId, groupName } = req.body;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  // Auto-register if session has a socket but is not registered
  if (session.sock && !session.registered) {
    console.log(`Auto-registering session ${sessionId} during set-group`);
    logToFile({ action: 'auto-register', sessionId, context: 'set-group' }, 'AUTO_REGISTER');
    session.registered = true;
  }
  
  if (!session.registered) {
    res.status(400).json({ error: 'Session not registered yet' });
    return;
  }
  
  try {
    // Get current groups to validate input
    const groups = await session.sock.groupFetchAllParticipating();
    const groupsList = Object.values(groups).map((g: any) => ({
      id: g.id,
      name: g.subject || 'No Name',
      participants: g.participants?.length || 0
    }));
    
    // If groupId is provided, validate and use it
    if (groupId) {
      const foundGroup = groupsList.find(g => g.id === groupId);
      if (foundGroup) {
        session.forwardGroupId = groupId;
        session.groupName = foundGroup.name;
        logToFile({ action: 'set-group-by-id', group: foundGroup.name, id: groupId }, 'SET_GROUP');
        
        res.json({
          success: true,
          message: `Manually set group to: ${foundGroup.name}`,
          forwardGroupId: session.forwardGroupId,
          groupName: session.groupName
        });
        return;
      } else {
        res.status(400).json({
          error: 'Invalid group ID',
          availableGroups: groupsList
        });
        return;
      }
    }
    
    // If groupName is provided, find the corresponding ID
    if (groupName) {
      const foundGroup = groupsList.find(g => 
        g.name.toLowerCase() === groupName.toLowerCase()
      );
      
      if (foundGroup) {
        session.forwardGroupId = foundGroup.id;
        session.groupName = foundGroup.name;
        logToFile({ action: 'set-group-by-name', group: foundGroup.name, id: foundGroup.id }, 'SET_GROUP');
        
        res.json({
          success: true,
          message: `Manually set group to: ${foundGroup.name}`,
          forwardGroupId: session.forwardGroupId,
          groupName: session.groupName
        });
        return;
      } else {
        res.status(400).json({
          error: 'Group name not found',
          availableGroups: groupsList
        });
        return;
      }
    }
    
    // Neither groupId nor groupName provided
    res.status(400).json({
      error: 'Missing groupId or groupName parameter',
      availableGroups: groupsList
    });
    
  } catch (error: any) {
    console.error('Failed to set group:', error);
    logToFile({ error: error.message }, 'SET_GROUP_ERROR');
    res.status(500).json({ 
      error: 'Failed to set group', 
      details: error.message 
    });
  }
});

// Test if the server is reachable
router.get('/ping', (req: Request, res: Response) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Test logging functionality
router.get('/test-log/:sessionId', (req: Request<{sessionId: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  try {
    // Create test log
    logToFile({
      test: 'This is a test log entry',
      timestamp: new Date().toISOString(),
      session: {
        id: sessionId,
        registered: session.registered,
        hasGroup: !!session.forwardGroupId
      }
    }, 'TEST');
    
    // Check if the log directory exists and is writable
    const logDir = path.resolve(process.cwd(), 'logs');
    const canWrite = fs.existsSync(logDir) && fs.accessSync(logDir, fs.constants.W_OK);
    
    res.json({
      status: 'Log created',
      logDirectory: logDir,
      directoryExists: fs.existsSync(logDir),
      writableDirectory: true,
      sessionStatus: {
        id: sessionId,
        registered: session.registered,
        hasConnection: !!session.sock,
        hasGroup: !!session.forwardGroupId,
        groupName: session.groupName
      }
    });
  } catch (error: any) {
    res.status(500).json({ 
      error: 'Failed to create test log', 
      details: error.message,
      stack: error.stack
    });
  }
});

// Check WebSocket connection status
router.get('/connection-status/:sessionId', async (req: Request<{sessionId: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  try {
    let connectionState = 'unknown';
    // Define interface to include potential error property
    interface SocketInfo {
      exists: boolean;
      error?: string;
    }
    const socketInfo: SocketInfo = { exists: !!session.sock };
    
    if (session.sock) {
      // Try to check if connection is alive
      try {
        const connectionInfo = await Promise.race([
          // Try to get business profile (a simple operation that requires connection)
          session.sock.getBusinessProfile(session.phoneNumber).then(() => 'connected'),
          // Timeout after 3 seconds
          new Promise(resolve => setTimeout(() => resolve('timeout'), 3000))
        ]);
        
        connectionState = connectionInfo === 'connected' ? 'active' : 'unavailable';
      } catch (error: any) {
        connectionState = 'error';
        socketInfo.error = String(error);
      }
    }
    
    res.json({
      status: 'OK',
      sessionId,
      registered: session.registered,
      connectionState,
      socketInfo,
      phoneNumber: session.phoneNumber,
      forwardGroupId: session.forwardGroupId,
      groupName: session.groupName
    });
  } catch (error: any) {
    res.status(500).json({ 
      error: 'Failed to check connection status', 
      details: error.message 
    });
  }
});

// Force trigger test message in the socket
router.post('/simulate-message/:sessionId', async (req: Request<{sessionId: string}, any, {text: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const { text } = req.body;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  if (!session.sock) {
    res.status(400).json({ error: 'No socket connection available' });
    return;
  }
  
  try {
    // Manually create a mock message and pass it to the message handler
    const mockMessage = {
      key: {
        remoteJid: `${session.phoneNumber}@s.whatsapp.net`,
        fromMe: false,
        id: 'TEST_' + Date.now()
      },
      message: {
        conversation: text || 'Re-envía: This is a test message'
      },
      messageTimestamp: Date.now() / 1000
    };
    
    // Log this test message
    logToFile(mockMessage, 'SIMULATED_MESSAGE');
    
    // Manually process this message
    if (text && text.match(/^(Re-envía:|Re-envia:|Re-envíá:|Reenvia:|Reenvía:)/) && session.forwardGroupId) {
        const prefixMatch = text.match(/^(Re-envía:|Re-envia:|Re-envíá:|Reenvia:|Reenvía:)\s*/);
        const prefixLength = prefixMatch ? prefixMatch[0].length : 0;
        const forwardText = text.substring(prefixLength).trim();
      await session.sock.sendMessage(session.forwardGroupId, { text: forwardText });
      res.json({
        success: true,
        message: 'Test message simulated and forwarded',
        forwardedTo: session.forwardGroupId,
        originalMessage: text,
        forwardedMessage: forwardText
      });
    } else {
      res.json({
        success: true,
        message: 'Test message simulated but not forwarded',
        reason: !text ? 'No text provided' : 
               !text.startsWith('Re-envía:') ? 'Text does not start with Re-envía:' :
               !session.forwardGroupId ? 'No forward group configured' : 'Unknown'
      });
    }
  } catch (error: any) {
    res.status(500).json({ 
      error: 'Failed to simulate message', 
      details: error.message 
    });
  }
});

// Add diagnostic testing endpoint
router.post('/trigger-diagnostic/:sessionId', async (req: Request<{sessionId: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  if (!session.sock) {
    res.status(400).json({ error: 'No socket connection available' });
    return;
  }
  
  try {
    logToFile({ 
      action: 'diagnostic-test',
      sessionId,
      time: new Date().toISOString(),
      socketInfo: {
        connected: !!session.sock,
        user: session.sock.user || null,
        registered: session.registered
      }
    }, 'DIAGNOSTIC');
    
    const socketId = session.sock.user?.id || 'unknown';
    const mappedSessionId = socketSessionMap.get(socketId);
    
    res.json({
      diagnosticResult: {
        serverTime: new Date().toISOString(),
        session: {
          id: sessionId,
          registered: session.registered,
          hasConnection: !!session.sock,
          hasGroup: !!session.forwardGroupId,
          groupName: session.groupName
        },
        socket: {
          id: socketId,
          mappedToSession: mappedSessionId,
          mappingCorrect: mappedSessionId === sessionId
        },
        messageHandlersActive: true,
        howToTest: "Send a message with 'Re-envía:' prefix from another WhatsApp number to this account"
      }
    });
  } catch (error: any) {
    res.status(500).json({ 
      error: 'Diagnostic failed', 
      details: error.message 
    });
  }
});

// View recent logs via HTTP
router.get('/debug-logs/:sessionId', (req: Request<{sessionId: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  try {
    const logDir = path.resolve(process.cwd(), 'logs');
    if (!fs.existsSync(logDir)) {
      res.json({ status: 'No logs found' });
      return;
    }
    
    const todayLog = path.join(logDir, `whatsapp-${new Date().toISOString().split('T')[0]}.log`);
    
    if (fs.existsSync(todayLog)) {
      const logs = fs.readFileSync(todayLog, 'utf8').split('\n').slice(-100); // Last 100 lines
      res.json({ 
        status: 'OK',
        sessionInfo: {
          registered: session.registered,
          hasGroup: !!session.forwardGroupId,
          groupName: session.groupName
        },
        recentLogs: logs 
      });
    } else {
      res.json({ 
        status: 'No logs for today',
        sessionInfo: {
          registered: session.registered,
          hasGroup: !!session.forwardGroupId,
          groupName: session.groupName
        }
      });
    }
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to retrieve logs', message: error.message });
  }
});

// Endpoint to change group settings to admin-only
router.post('/group-settings/:sessionId', async (req: Request<{sessionId: string}, any, {groupId?: string, adminsOnly?: boolean}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const { groupId, adminsOnly = true } = req.body;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  if (!session.registered) {
    res.status(400).json({ error: 'Session not registered yet' });
    return;
  }
  
  // Use provided groupId or the session's forwardGroupId
  const targetGroupId = groupId || session.forwardGroupId;
  
  if (!targetGroupId) {
    res.status(400).json({ error: 'No group ID specified or found in session' });
    return;
  }
  
  try {
    // Attempt to update group settings
    // 'announcement' = only admins can send messages
    // 'not_announcement' = everyone can send messages
    await session.sock.groupSettingUpdate(
      targetGroupId,
      adminsOnly ? 'announcement' : 'not_announcement'
    );
    
    logToFile({ 
      action: 'update-group-settings', 
      groupId: targetGroupId, 
      adminsOnly 
    }, 'GROUP_SETTINGS');
    
    res.json({
      success: true,
      message: `Group settings updated. Only admins can send messages: ${adminsOnly}`,
      groupId: targetGroupId
    });
  } catch (error: any) {
    console.error('Failed to update group settings:', error);
    logToFile({ error: error.message }, 'GROUP_SETTINGS_ERROR');
    res.status(500).json({ 
      error: 'Failed to update group settings', 
      details: error.message,
      hint: 'You may need to be a group admin to change these settings'
    });
  }
});

// Setup alternative message forwarding from any source
router.post('/forward-message/:sessionId', async (req: Request<{sessionId: string}, any, {message: string, sourceNumber?: string, sourceName?: string}>, res: Response) => {
  const sessionId = req.params.sessionId;
  const { message, sourceNumber = "Unknown", sourceName = "External" } = req.body;
  const session = sessions.get(sessionId);
  
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  
  if (!session.forwardGroupId) {
    res.status(400).json({ error: 'No forward group configured' });
    return;
  }
  
  if (!message) {
    res.status(400).json({ error: 'No message provided' });
    return;
  }
  
  try {
    // Format message and forward to group
    let internalMessage = message;
    let forwardText = message;

    const prefixMatch = message.match(/^(Re-envía:|Re-envia:|Re-envíá:|Reenvia:|Reenvía:)\s*/);

    if (prefixMatch) {
        // Keep track of the original message with prefix
        internalMessage = message;
        // Remove prefix for forwarding
        forwardText = message.substring(prefixMatch[0].length).trim();
      } else {
        // Create internal version with prefix for tracking
        internalMessage = `Re-envía: [From: ${sourceName} (${sourceNumber})]\n${message}`;
        // Forward the message without prefix
        forwardText = `[From: ${sourceName} (${sourceNumber})]\n${message}`;
      }
      
      await session.sock.sendMessage(session.forwardGroupId, { 
        text: forwardText // Send without prefix
      });
    
    logToFile({
        action: 'forward-message',
        source: { name: sourceName, number: sourceNumber },
        internalMessage: internalMessage,
        forwardedMessage: forwardText
      }, 'MANUAL_FORWARD');
    
    res.json({
        success: true,
        message: 'Message forwarded to group',
        forwardedTo: session.forwardGroupId,
        internalMessage: internalMessage,
        forwardedMessage: forwardText
    });
  } catch (error: any) {
    logToFile({ error: error.message }, 'MANUAL_FORWARD_ERROR');
    res.status(500).json({
      error: 'Failed to forward message',
      details: error.message
    });
  }
});

// Mount the router to the app
app.use('/', router);

// Start server with global handlers setup
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  // Setup global message handlers
  setupGlobalMessageHandlers();
  
  // Initial check after 5 seconds to allow connections to initialize
  setTimeout(autoCheckSessions, 5000);
  
  // Setup periodic checking
  setInterval(autoCheckSessions, 120000);
});