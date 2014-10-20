/*
 * Copyright 2011 The Ohio State University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.osu.ocio.shibboleth.logback;

import java.util.ArrayList;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.boolex.EvaluationException;
import ch.qos.logback.core.boolex.EventEvaluatorBase;

/**
 * Custom evaluator for logback filters based on a message to match on.
 * 
 * @author Scott Cantor
 */
public class MessageEventEvaluator extends EventEvaluatorBase<ILoggingEvent> {

	private ArrayList<String> messages;

	public MessageEventEvaluator() {
		messages = new ArrayList<String>();
	}
	
	/**
	 * Adds a message to match.
	 * @param m	message to match
	 */
	public void addMessage(String m) {
		messages.add(m);
	}
	
	public boolean evaluate(ILoggingEvent e) throws NullPointerException,
			EvaluationException {
		if (e != null) {
			String m = e.getFormattedMessage();
			if (m != null) {
				for (String i : messages) {
					if (m.contains(i)) {
						return true;
					}
				}
			}
			
			IThrowableProxy ex = e.getThrowableProxy();
			if (ex != null) {
				String n = ex.getMessage();
				if (n != null) {
					for (String i : messages) {
						if (n.contains(i)) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

}
