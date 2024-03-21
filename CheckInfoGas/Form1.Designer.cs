namespace CheckInfoGas
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            btnStart = new System.Windows.Forms.Button();
            cbLQ = new System.Windows.Forms.CheckBox();
            cbInfo = new System.Windows.Forms.CheckBox();
            dgv = new System.Windows.Forms.DataGridView();
            cStt = new System.Windows.Forms.DataGridViewTextBoxColumn();
            cUsername = new System.Windows.Forms.DataGridViewTextBoxColumn();
            cPassword = new System.Windows.Forms.DataGridViewTextBoxColumn();
            cStatus = new System.Windows.Forms.DataGridViewTextBoxColumn();
            contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(components);
            importToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            numThread = new System.Windows.Forms.NumericUpDown();
            label1 = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)dgv).BeginInit();
            contextMenuStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)numThread).BeginInit();
            SuspendLayout();
            // 
            // btnStart
            // 
            btnStart.Location = new System.Drawing.Point(10, 12);
            btnStart.Margin = new System.Windows.Forms.Padding(2);
            btnStart.Name = "btnStart";
            btnStart.Size = new System.Drawing.Size(97, 30);
            btnStart.TabIndex = 0;
            btnStart.Text = "Start";
            btnStart.UseVisualStyleBackColor = true;
            btnStart.Click += btnStart_Click;
            // 
            // cbLQ
            // 
            cbLQ.AutoSize = true;
            cbLQ.Location = new System.Drawing.Point(448, 18);
            cbLQ.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            cbLQ.Name = "cbLQ";
            cbLQ.Size = new System.Drawing.Size(77, 19);
            cbLQ.TabIndex = 2;
            cbLQ.Text = "Check LQ";
            cbLQ.UseVisualStyleBackColor = true;
            // 
            // cbInfo
            // 
            cbInfo.AutoSize = true;
            cbInfo.Location = new System.Drawing.Point(350, 18);
            cbInfo.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            cbInfo.Name = "cbInfo";
            cbInfo.Size = new System.Drawing.Size(83, 19);
            cbInfo.TabIndex = 3;
            cbInfo.Text = "Check Info";
            cbInfo.UseVisualStyleBackColor = true;
            // 
            // dgv
            // 
            dgv.AllowUserToAddRows = false;
            dgv.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            dgv.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            dgv.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            dgv.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] { cStt, cUsername, cPassword, cStatus });
            dgv.ContextMenuStrip = contextMenuStrip1;
            dgv.Location = new System.Drawing.Point(14, 65);
            dgv.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            dgv.Name = "dgv";
            dgv.RowHeadersVisible = false;
            dgv.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            dgv.Size = new System.Drawing.Size(720, 344);
            dgv.TabIndex = 1;
            // 
            // cStt
            // 
            cStt.FillWeight = 25F;
            cStt.HeaderText = "#";
            cStt.Name = "cStt";
            // 
            // cUsername
            // 
            cUsername.FillWeight = 50F;
            cUsername.HeaderText = "Username";
            cUsername.Name = "cUsername";
            // 
            // cPassword
            // 
            cPassword.FillWeight = 50F;
            cPassword.HeaderText = "Password";
            cPassword.Name = "cPassword";
            // 
            // cStatus
            // 
            cStatus.FillWeight = 130F;
            cStatus.HeaderText = "Status";
            cStatus.Name = "cStatus";
            // 
            // contextMenuStrip1
            // 
            contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] { importToolStripMenuItem });
            contextMenuStrip1.Name = "contextMenuStrip1";
            contextMenuStrip1.Size = new System.Drawing.Size(111, 26);
            // 
            // importToolStripMenuItem
            // 
            importToolStripMenuItem.Name = "importToolStripMenuItem";
            importToolStripMenuItem.Size = new System.Drawing.Size(110, 22);
            importToolStripMenuItem.Text = "Import";
            importToolStripMenuItem.Click += importToolStripMenuItem_Click;
            // 
            // numThread
            // 
            numThread.Location = new System.Drawing.Point(182, 16);
            numThread.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            numThread.Maximum = new decimal(new int[] { 1000, 0, 0, 0 });
            numThread.Name = "numThread";
            numThread.Size = new System.Drawing.Size(56, 23);
            numThread.TabIndex = 4;
            numThread.Value = new decimal(new int[] { 1, 0, 0, 0 });
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(114, 18);
            label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(57, 15);
            label1.TabIndex = 5;
            label1.Text = "Số luồng:";
            // 
            // Form1
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(765, 422);
            Controls.Add(label1);
            Controls.Add(numThread);
            Controls.Add(dgv);
            Controls.Add(cbInfo);
            Controls.Add(cbLQ);
            Controls.Add(btnStart);
            Margin = new System.Windows.Forms.Padding(2);
            Name = "Form1";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "Form1";
            ((System.ComponentModel.ISupportInitialize)dgv).EndInit();
            contextMenuStrip1.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)numThread).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private System.Windows.Forms.Button btnStart;
        private System.Windows.Forms.CheckBox cbLQ;
        private System.Windows.Forms.CheckBox cbInfo;
        private System.Windows.Forms.DataGridView dgv;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem importToolStripMenuItem;
        private System.Windows.Forms.NumericUpDown numThread;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.DataGridViewTextBoxColumn cStt;
        private System.Windows.Forms.DataGridViewTextBoxColumn cUsername;
        private System.Windows.Forms.DataGridViewTextBoxColumn cPassword;
        private System.Windows.Forms.DataGridViewTextBoxColumn cStatus;
    }
}

